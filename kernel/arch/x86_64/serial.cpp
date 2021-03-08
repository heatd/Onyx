/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>

#include <onyx/port_io.h>
#include <onyx/serial.h>
#include <onyx/tty.h>
#include <onyx/irq.h>
#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/driver.h>

enum class uart8250_register
{
	data = 0,
	interrupt_enable = 1,
	/* When DLAB is set, regs 0 and 1 get re-assigned to lsb and msb of the divisor */
	lsb_divisor = 0,
	msb_divisor = 1,
	fifo_control,
	interrupt_identification = 2,		/* It's FCR when written, IIR when read */
	line_control,
	modem_control,
	line_status,
	modem_status,
	scratch_register
};

#define UART8250_LCR_DLAB				(1 << 7)
#define UART8250_LCR_SBE				(1 << 6)
#define UART8250_LCR_2_STOP_BITS		(1 << 2)
#define UART8250_LCR_WORD_LENGTH(x)		(x << 0)
#define UART8250_LCR_8BIT_WL			3
#define UART8250_LCR_7BIT_WL			2
#define UART8250_LCR_6BIT_WL			1
#define UART8250_LCR_5BIT_WL			0

#define UART8250_FCR_FIFO_ENABLE		(1 << 0)
#define UART8250_FCR_CLR_RCV_FIFO		(1 << 1)
#define UART8250_FCR_CLR_TX_FIFO		(1 << 2)
#define UART8250_FCR_DMA_MODE_SEL		(1 << 3)
#define UART8250_FCR_EN_64B_FIFO		(1 << 5)
#define UART8250_FCR_INT_TRIGGER_4BYTE	(1 << 6)
#define UART8250_FCR_INT_TRIGGER_8BYTE  (2 << 6)
#define UART8250_FCR_INT_TRIGGER_14BYTE (3 << 6)

#define UART8250_MCR_DATA_TERMINAL_RDY  (1 << 0)
#define UART8250_MCR_REQ_TO_SEND        (1 << 1)
#define UART8250_MCR_GPO2_ENABLE        (1 << 3)
#define UART8250_MCR_LOOPBACK           (1 << 4)

#define UART8250_LSR_DATA_RDY     (1 << 0)
#define UART8250_LSR_OVERRUN_ERR  (1 << 1)
#define UART8250_LSR_PARITY_ERR   (1 << 2)
#define UART8250_LSR_FRAMING_ERR  (1 << 3)
#define UART8250_LSR_BREAK_INDIC  (1 << 4)
#define UART8250_LSR_TX_BUF_EMPTY (1 << 5)
#define UART8250_LSR_TX_EMPTY     (1 << 6)

#define UART8250_IER_DATA_AVAIL   (1 << 0)
#define UART8250_IER_TX_EMPTY     (1 << 1)
#define UART8250_IER_ERR          (1 << 2)
#define UART8250_IER_STATUS_CHNG  (1 << 3)

#define UART8250_IIR_IRQ_PENDING  (1 << 0)
#define UART8250_IIR_REASON(x)    (x & (0x7 << 1))
#define UART8250_IIR_RX_DATA_AVL  (1 << 2)

extern "C"
int vterm_receive_input(char c);

struct driver serial_platform_driver = 
{
	.name = "uart8250"
};

struct device uart8250_platform_device = {.name = "uart8250"};

class uart8250_port : public serial_port
{
	uint16_t io_port;
	int com_nr;

	static constexpr uint32_t serial_clock = 115200;
	static constexpr uint16_t default_baud_rate = 38400;

	template <typename T>
	T read(uart8250_register reg)
	{
		auto port = io_port + static_cast<uint16_t>(reg);

		static_assert(sizeof(T) <= 4, "Can't do reads larger than 4-bytes long");

		if constexpr(sizeof(T) == 1)
			return inb(port);
		else if constexpr(sizeof(T) == 2)
			return inw(port);
		else if constexpr(sizeof(T) == 4)
			return inl(port);
	}

	template <typename T>
	void write(uart8250_register reg, T val)
	{
		auto port = io_port + static_cast<uint16_t>(reg);

		static_assert(sizeof(T) <= 4, "Can't do writes larger than 4-bytes long");

		if constexpr(sizeof(T) == 1)
			outb(port, val);
		else if constexpr(sizeof(T) == 2)
			outw(port, val);
		else if constexpr(sizeof(T) == 4)
			outl(port, val);
	}

	static constexpr uint16_t calculate_divisor(uint16_t rate)
	{
		return serial_clock / rate;
	}

	bool tx_empty();
	bool rx_rdy();

	void write_byte(uint8_t byte);
	void set_baud_rate(uint16_t rate);

	bool present();
	bool test();

	void dispatch_rx();
public:
	uart8250_port(uint16_t io_port, int com_nr) : io_port(io_port), com_nr(com_nr)
	{
		init_wait_queue_head(&rcv_wait);
	}

	bool init();

	void late_init();

	void write(const char *s, size_t length);

	irqstatus_t on_irq();
};

void do_dispatch(void *ctx)
{
	uint8_t data = (uint8_t) (unsigned long) ctx;
	//vterm_receive_input(data);
	(void) data;
}

void uart8250_port::dispatch_rx()
{
	auto data = read<uint8_t>(uart8250_register::data);
	struct dpc_work work;
	work.context = (void *) (unsigned long) data;
	work.funcptr = do_dispatch;
	work.next = NULL;

	dpc_schedule_work(&work, DPC_PRIORITY_HIGH);
}

irqstatus_t uart8250_port::on_irq()
{
	auto st = read<uint8_t>(uart8250_register::interrupt_identification);

	if(!(st & UART8250_IIR_IRQ_PENDING))
		return IRQ_UNHANDLED;

	auto reason = UART8250_IIR_REASON(st);
	if(reason == UART8250_IIR_RX_DATA_AVL)
	{
		dispatch_rx();
		return IRQ_HANDLED;
	}

	return IRQ_UNHANDLED;
}

void uart8250_port::set_baud_rate(uint16_t rate)
{
	auto div_value = calculate_divisor(rate);

	assert(div_value != 0);

	uint8_t old_val = read<uint8_t>(uart8250_register::line_control);
	write<uint8_t>(uart8250_register::line_control, old_val | UART8250_LCR_DLAB);
	write<uint8_t>(uart8250_register::lsb_divisor, div_value & 0xff);
	write<uint8_t>(uart8250_register::msb_divisor, div_value >> 8);

	write<uint8_t>(uart8250_register::line_control, old_val);
}

bool uart8250_port::test()
{
	write<uint8_t>(uart8250_register::modem_control, UART8250_MCR_LOOPBACK);
	write<uint8_t>(uart8250_register::data, 0xcd);

	return read<uint8_t>(uart8250_register::data) == 0xcd;
}

bool uart8250_port::tx_empty()
{
	return read<uint8_t>(uart8250_register::line_status) & UART8250_LSR_TX_BUF_EMPTY;
}

bool uart8250_port::rx_rdy()
{
	return read<uint8_t>(uart8250_register::line_status) & UART8250_LSR_DATA_RDY;
}

void uart8250_port::write_byte(uint8_t c)
{
	while(!tx_empty());

	write<uint8_t>(uart8250_register::data, c);
	if(c == '\n')
		write_byte('\r');
}

void uart8250_port::write(const char *s, size_t size)
{
	for(size_t i = 0; i < size; i++)
	{
		write_byte(static_cast<uint8_t>(*(s + i)));
	}
}

uart8250_port com1{0x3f8, 1};

bool uart8250_port::present()
{
	static constexpr uint8_t test_val = 0xcd;
	write<uint8_t>(uart8250_register::scratch_register, test_val);

	auto present = read<uint8_t>(uart8250_register::scratch_register);

	return present == test_val;
}

irqstatus_t uart8250_irq(irq_context *ctx, void *cookie)
{
	auto port = reinterpret_cast<uart8250_port*>(cookie);

	return port->on_irq();
}

bool uart8250_port::init()
{
	/* Disable interrupts */
	write<uint8_t>(uart8250_register::interrupt_enable, 0);

	/* Then we set the baud rate of the port */
	set_baud_rate(default_baud_rate);

	/* Set the word length to 8-bits per word */
	write<uint8_t>(uart8250_register::line_control, UART8250_LCR_WORD_LENGTH(UART8250_LCR_8BIT_WL));

	/* Set some FIFO settings */
	uint8_t fcr = UART8250_FCR_CLR_TX_FIFO | UART8250_FCR_CLR_RCV_FIFO | UART8250_FCR_FIFO_ENABLE |
                  UART8250_FCR_INT_TRIGGER_14BYTE;
	
	write<uint8_t>(uart8250_register::fifo_control, fcr);
	
	/* Signal that we're ready to send and ready to receive */
	write<uint8_t>(uart8250_register::modem_control, UART8250_MCR_GPO2_ENABLE | UART8250_MCR_DATA_TERMINAL_RDY
                   | UART8250_MCR_REQ_TO_SEND);

	/* Re-enable interrupts */
	write<uint8_t>(uart8250_register::interrupt_enable, UART8250_IER_DATA_AVAIL);
	
	return true;
}

void uart8250_port::late_init()
{
	auto int_no = com_nr == 1 || com_nr == 3  ? 4 : 3;

	uart8250_platform_device.driver = &serial_platform_driver;
	install_irq(int_no, uart8250_irq, &uart8250_platform_device, IRQ_FLAG_REGULAR, this);
}

bool com1_init = false;

void platform_serial_init(void)
{
	com1_init = com1.init();	
}

int platform_serial_late_init()
{
	com1.late_init();
	return 0;
}

DRIVER_INIT(platform_serial_late_init);

void serial_write(const char *s, size_t size, struct serial_port *port)
{
	uart8250_port *p = reinterpret_cast<uart8250_port *>(port);

	p->write(s, size);
}

void platform_serial_write(const char *s, size_t size)
{
	serial_write(s, size, &com1);
}

serial_port *platform_get_main_serial()
{
	return com1_init ? &com1 : nullptr;
}
