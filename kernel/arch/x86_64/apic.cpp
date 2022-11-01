/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <fractions.h>
#include <stdbool.h>

#include <onyx/acpi.h>
#include <onyx/clock.h>
#include <onyx/cpu.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/process.h>
#include <onyx/registers.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/vm.h>
#include <onyx/x86/apic.h>
#include <onyx/x86/idt.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/pit.h>
#include <onyx/x86/tsc.h>

// #define CONFIG_APIC_PERIODIC

volatile uint32_t *bsp_lapic = NULL;
volatile uint64_t core_stack = 0;
PER_CPU_VAR(uint32_t lapic_id) = 0;

/**
 * @brief Writes to a LAPIC register.
 *
 * @param lapic LAPIC base.
 * @param addr Register to be written..
 * @param val Value to be written.
 */
void lapic_write(volatile uint32_t *lapic, uint32_t addr, uint32_t val)
{
    volatile uint32_t *laddr = (volatile uint32_t *) ((volatile char *) lapic + addr);
    *laddr = val;
}

/**
 * @brief Reads from a LAPIC register.
 *
 * @param lapic LAPIC base.
 * @param addr Register to be read..
 * @return The value of the register.
 */
uint32_t lapic_read(volatile uint32_t *lapic, uint32_t addr)
{
    volatile uint32_t *laddr = (volatile uint32_t *) ((volatile char *) lapic + addr);
    return *laddr;
}

PER_CPU_VAR(volatile uint32_t *lapic) = NULL;

/**
 * @brief Sends an EOI (end of interrupt) to the current LAPIC.
 *
 */
void lapic_send_eoi()
{
    lapic_write(get_per_cpu(lapic), LAPIC_EOI, 0);
}

extern struct clocksource tsc_clock;

static bool tsc_deadline_supported = false;

/**
 * @brief Initialises the current CPU's LAPIC.
 *
 */
void lapic_init(void)
{
    /* Get the BSP's LAPIC base address from the msr's */
    uint64_t addr = rdmsr(IA32_APIC_BASE);
    addr &= 0xFFFFF000;
    /* Map the BSP's LAPIC */
    bsp_lapic =
        (volatile uint32_t *) mmiomap((void *) addr, PAGE_SIZE, VM_READ | VM_WRITE | VM_NOCACHE);

    assert(bsp_lapic != NULL);

    /* Enable the LAPIC by setting LAPIC_SPUINT to 0x100 OR'd with the default spurious IRQ(15) */
    lapic_write(bsp_lapic, LAPIC_SPUINT, 0x100 | APIC_DEFAULT_SPURIOUS_IRQ);

    /* Send an EOI because some interrupts might've gotten stuck when the interrupts weren't enabled
     */
    lapic_write(bsp_lapic, LAPIC_EOI, 0);

    /* Set the task pri to 0 */
    lapic_write(bsp_lapic, LAPIC_TSKPRI, 0);
    tsc_deadline_supported = x86_has_cap(X86_FEATURE_TSC_DEADLINE);

    if (tsc_deadline_supported)
    {
        printf("tsc: TSC deadline mode supported\n");
    }

    write_per_cpu(lapic, bsp_lapic);
}

volatile char *ioapic_base = NULL;
ACPI_TABLE_MADT *madt = NULL;

/**
 * @brief Reads an IO APIC register.
 *
 * @param reg Register to be read.
 * @return Value of the register.
 */
uint32_t read_io_apic(uint32_t reg)
{
    uint32_t volatile *ioapic = (uint32_t volatile *) ioapic_base;
    ioapic[0] = (reg & 0xFF);
    return ioapic[4];
}

/**
 * @brief Writes to an IO APIC register.
 *
 * @param reg Register to be written to.
 * @param value Value to write.
 */
void write_io_apic(uint32_t reg, uint32_t value)
{
    uint32_t volatile *ioapic = (uint32_t volatile *) ioapic_base;
    ioapic[0] = (reg & 0xFF);
    ioapic[4] = value;
}

/**
 * @brief Reads an IO APIC pin's redirection entry.
 *
 * @param pin Interrupt pin.
 * @return The pin's redirection entry.
 */
uint64_t read_redirection_entry(uint32_t pin)
{
    uint64_t ret;
    ret = (uint64_t) read_io_apic(0x10 + pin * 2);
    ret |= (uint64_t) read_io_apic(0x10 + pin * 2 + 1) << 32;
    return ret;
}

/**
 * @brief Writes to an IO APIC pin's redirection entry.
 *
 * @param pin Interrupt pin.
 * @param value Redirection entry to write.
 */
void write_redirection_entry(uint32_t pin, uint64_t value)
{
    write_io_apic(0x10 + pin * 2, value & 0x00000000FFFFFFFF);
    write_io_apic(0x10 + pin * 2 + 1, value >> 32);
}

static int irqs;

/**
 * @brief Sets up the redirection entry of a pin.
 *
 * @param active_high Whether the interrupt pin should be active high.
 * @param level Whether the interrupt pin should be level triggered(instead of edge).
 * @param pin Interrupt pin to set up.
 */
void ioapic_set_pin(bool active_high, bool level, uint32_t pin)
{
    uint64_t entry = 0;
    entry |= irqs + pin;

    if (!active_high)
    {
        /* Active low */
        entry |= IOAPIC_PIN_POLARITY_ACTIVE_LOW;
    }

    if (level)
    {
        entry |= IOAPIC_PIN_TRIGGER_LEVEL;
    }

    write_redirection_entry(pin, entry);
}

/**
 * @brief Unmasks an interrupt pin.
 *
 * @param pin Pin to unmask.
 */
void ioapic_unmask_pin(uint32_t pin)
{
    uint64_t entry = read_redirection_entry(pin);
    entry &= ~IOAPIC_PIN_MASKED;
    write_redirection_entry(pin, entry);
}

/**
 * @brief Masks an interrupt pin.
 *
 * @param pin Pin to mask.
 */
void ioapic_mask_pin(uint32_t pin)
{
    /*printk("Masking pin %u\n", pin);*/
    uint64_t entry = read_redirection_entry(pin);
    entry |= IOAPIC_PIN_MASKED;
    write_redirection_entry(pin, entry);
}

#ifndef CONFIG_ACPI

ACPI_STATUS AcpiGetTable(ACPI_STRING name, UINT32 instance, ACPI_TABLE_HEADER **out)
{
    return AE_NOT_IMPLEMENTED;
}

#endif

void set_pin_handlers(void)
{
    /* Allocate a pool of vectors and reserve them */
    irqs = x86_allocate_vectors(24);
    x86_reserve_vector(irqs + 0, irq0);
    x86_reserve_vector(irqs + 1, irq1);
    x86_reserve_vector(irqs + 2, irq2);
    x86_reserve_vector(irqs + 3, irq3);
    x86_reserve_vector(irqs + 4, irq4);
    x86_reserve_vector(irqs + 5, irq5);
    x86_reserve_vector(irqs + 6, irq6);
    x86_reserve_vector(irqs + 7, irq7);
    x86_reserve_vector(irqs + 8, irq8);
    x86_reserve_vector(irqs + 9, irq9);
    x86_reserve_vector(irqs + 10, irq10);
    x86_reserve_vector(irqs + 11, irq11);
    x86_reserve_vector(irqs + 12, irq12);
    x86_reserve_vector(irqs + 13, irq13);
    x86_reserve_vector(irqs + 14, irq14);
    x86_reserve_vector(irqs + 15, irq15);
    x86_reserve_vector(irqs + 16, irq16);
    x86_reserve_vector(irqs + 17, irq17);
    x86_reserve_vector(irqs + 18, irq18);
    x86_reserve_vector(irqs + 19, irq19);
    x86_reserve_vector(irqs + 20, irq20);
    x86_reserve_vector(irqs + 21, irq21);
    x86_reserve_vector(irqs + 22, irq22);
    x86_reserve_vector(irqs + 23, irq23);
    // The MADT's signature is "APIC"
    ACPI_STATUS st = AcpiGetTable((ACPI_STRING) "APIC", 0, (ACPI_TABLE_HEADER **) &madt);
    if (ACPI_FAILURE(st))
        panic("Failed to get the MADT");

    ACPI_SUBTABLE_HEADER *first = (ACPI_SUBTABLE_HEADER *) (madt + 1);
    for (int i = 0; i < 24; i++)
    {
        if (i <= 19)
        {
            // ISA Interrupt, set it like a standard ISA interrupt
            /*
             * ISA Interrupts have the following attributes:
             * - Active High
             * - Edge triggered
             * - Fixed delivery mode
             * They might be overwriten by the ISO descriptors in the MADT
             */
            uint64_t entry = IOAPIC_PIN_MASKED;
            entry = entry | (irqs + i);
            write_redirection_entry(i, entry);
        }

        uint64_t entry = IOAPIC_PIN_MASKED;
        write_redirection_entry(i, entry | (irqs + i));
    }

    for (ACPI_SUBTABLE_HEADER *i = first;
         i < (ACPI_SUBTABLE_HEADER *) ((char *) madt + madt->Header.Length);
         i = (ACPI_SUBTABLE_HEADER *) ((uint64_t) i + (uint64_t) i->Length))
    {
        if (i->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE)
        {
            ACPI_MADT_INTERRUPT_OVERRIDE *mio = (ACPI_MADT_INTERRUPT_OVERRIDE *) i;
            INFO("apic", "Interrupt override for GSI %d to %d\n", mio->SourceIrq, mio->GlobalIrq);
            uint64_t red = read_redirection_entry(mio->GlobalIrq);
            red |= 32 + mio->GlobalIrq;
            if ((mio->IntiFlags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW)
                red |= (1 << 13);
            else
                red &= ~(1 << 13);

            if ((mio->IntiFlags & ACPI_MADT_TRIGGER_LEVEL) == ACPI_MADT_TRIGGER_LEVEL)
                red |= (1 << 15);
            else
                red &= ~(1 << 15);

            printf("GSI %d %s:%s\n", mio->GlobalIrq, red & (1 << 13) ? "low" : "high",
                   red & (1 << 15) ? "level" : "edge");
            write_redirection_entry(mio->GlobalIrq, red);
        }
    }
}

void ioapic_early_init(void)
{
    /* TODO: Detecting I/O APICs should be a good idea */
    /* Map the I/O APIC base */
    ioapic_base = (volatile char *) mmiomap((void *) IOAPIC_BASE_PHYS, PAGE_SIZE,
                                            VM_READ | VM_WRITE | VM_NOCACHE);
    assert(ioapic_base != NULL);
}

void ioapic_init()
{
#ifdef CONFIG_ACPI
    /* Execute _PIC */
    acpi_execute_pic(ACPI_PIC_IOAPIC);
#endif
    /* Set each APIC pin's polarity, flags, and vectors to their defaults */
    set_pin_handlers();
}

static uint64_t boot_ticks = 0;

void apic_update_clock_monotonic(void)
{
    struct clock_time time;
    time.epoch = boot_ticks / 1000;

    /* It's actually possible that no clocksource exists this early on */
    struct clocksource *source = get_main_clock();
    if (source)
    {
        time.tick = source->get_ticks();
        time.epoch = source->get_ns() / NS_PER_SEC;
        time.source = source;
    }

    time_set(CLOCK_MONOTONIC, &time);
}

void apic_set_oneshot(hrtime_t deadline);

PER_CPU_VAR(unsigned long apic_ticks) = 0;
PER_CPU_VAR(struct timer lapic_timer);
extern uint32_t sched_quantum;

irqstatus_t apic_timer_irq(struct irq_context *ctx, void *cookie)
{
    add_per_cpu(apic_ticks, 1);

    /* Let cpu 0 update the boot ticks and the monotonic clock */
    if (get_cpu_nr() == 0)
    {
        boot_ticks++;
        apic_update_clock_monotonic();
    }

    timer_handle_events(get_per_cpu_ptr(lapic_timer));

    return IRQ_HANDLED;
}

unsigned long apic_rate = 0;
unsigned long us_apic_rate = 0;

driver apic_driver = {.name = "apic-timer", .bus_type_node = {&apic_driver}};

device apic_timer_dev{"apic-timer", nullptr, nullptr};

struct tsc_calib_context
{
    uint64_t init_tsc;
    uint64_t end_tsc;
    uint64_t best_delta;
};

#define CALIBRATION_TRIALS 3
#define CALIBRATION_TRIES  3
struct calibration_context
{
    uint32_t duration[CALIBRATION_TRIALS];
    struct tsc_calib_context tsc_calib[CALIBRATION_TRIALS];
    uint32_t apic_ticks[CALIBRATION_TRIALS];
};

struct calibration_context calib = {};

void apic_calibration_setup_count(int try_)
{
    (void) try_;
    /* 0xFFFFFFFF shouldn't overflow in 10ms */
    lapic_write(bsp_lapic, LAPIC_TIMER_INITCNT, UINT32_MAX);
}

void tsc_calibration_setup_count(int try_)
{
    calib.tsc_calib[try_].init_tsc = rdtsc();
}

void tsc_calibration_end(int try_)
{
    calib.tsc_calib[try_].end_tsc = rdtsc();
}

void apic_calibration_end(int try_)
{
    /* Get the ticks that passed in the time frame */
    uint32_t ticks = UINT32_MAX - lapic_read(bsp_lapic, LAPIC_TIMER_CURRCNT);
    if (ticks < calib.apic_ticks[try_])
        calib.apic_ticks[try_] = ticks;
}

void apic_calibrate(int try_)
{
    calib.apic_ticks[try_] = UINT32_MAX;

    for (int i = 0; i < CALIBRATION_TRIALS; i++)
    {
        uint32_t freq = 1000 / calib.duration[try_];
        pit_init_oneshot(freq);

        apic_calibration_setup_count(try_);

        pit_wait_for_oneshot();

        apic_calibration_end(try_);

        pit_stop();
    }
}

void tsc_calibrate(int try_)
{
    calib.tsc_calib[try_].best_delta = UINT64_MAX;

    for (int i = 0; i < CALIBRATION_TRIALS; i++)
    {
        uint32_t freq = 1000 / calib.duration[try_];
        pit_init_oneshot(freq);

        tsc_calibration_setup_count(try_);

        pit_wait_for_oneshot();

        tsc_calibration_end(try_);

        uint64_t delta = calib.tsc_calib[try_].end_tsc - calib.tsc_calib[try_].init_tsc;

        if (delta < calib.tsc_calib[try_].best_delta)
            calib.tsc_calib[try_].best_delta = delta;

        pit_stop();
    }
}

unsigned long calculate_frequency(unsigned long *deltas, unsigned long x)
{
    /* Lets do a regression analysis. f(x) = mx + b */

    /* Find m = (yf - yi)/(xf - xi) */
    /* Use the Theil–Sen estimator method to get m and b */

    /* Since we have 3 deltas we'll have two pairs of points to work with
     * and then after calculating the different slopes we'll have to get the
     * median. */

    unsigned long slopes[2];
    slopes[0] = INT_DIV_ROUND_CLOSEST(deltas[1] - deltas[0], calib.duration[1] - calib.duration[0]);
    slopes[1] = INT_DIV_ROUND_CLOSEST(deltas[2] - deltas[1], calib.duration[2] - calib.duration[1]);

    unsigned long slope = INT_DIV_ROUND_CLOSEST(slopes[1] + slopes[0], 2);

    /* b is found out by the median of yi - mxi.
      Since we have 3 values, we use index 1 */

    long b = deltas[1] - slope * calib.duration[1];

    /* Now do f(x) */
    unsigned long freq = slope * x - b;

    return freq;
}

void timer_calibrate(void)
{
    /* After eyeballing results, I can tell that the PIT gives us better results in QEMU.
     * Should we switch?
     */
    // if(apic_calibrate_acpi() == false)
    calib.duration[0] = 2;
    calib.duration[1] = 5;
    calib.duration[2] = 10;
    /* No need to cal*/
    bool calibrate_tsc = x86_get_tsc_rate() == 0;

    for (int i = 0; i < CALIBRATION_TRIALS; i++)
    {
        apic_calibrate(i);
        if (calibrate_tsc)
            tsc_calibrate(i);
    }

    unsigned long deltas[3];

    for (int i = 0; i < 3; i++)
    {
        deltas[i] = calib.tsc_calib[i].best_delta;
    }

    if (calibrate_tsc)
        x86_set_tsc_rate(calculate_frequency(deltas, 1000));

    for (int i = 0; i < 3; i++)
    {
        deltas[i] = calib.apic_ticks[i];
    }

    apic_rate = calculate_frequency(deltas, 1);
}

extern struct clocksource tsc_clock;

void apic_set_oneshot_tsc(hrtime_t deadline)
{
    uint64_t future_tsc_counter = tsc_get_counter_from_ns(deadline);

    lapic_write(get_per_cpu(lapic), LAPIC_LVT_TIMER, 34 | LAPIC_LVT_TIMER_MODE_TSC_DEADLINE);
    wrmsr(IA32_TSC_DEADLINE, future_tsc_counter);
}

struct fp_32_64 apic_ticks_per_ns;

void apic_set_oneshot_apic(hrtime_t deadline)
{
    hrtime_t now = clocksource_get_time();

    hrtime_t delta = deadline - now;

    /* Clamp the delta */
    if (deadline < now)
        delta = 0;

    if (delta == 0)
    {
        delta = 1;
    }

    uint64_t counter64 = u64_mul_u64_fp32_64(delta, apic_ticks_per_ns);
    if (counter64 >> 32)
        counter64 = UINT32_MAX;

    uint32_t counter = (uint32_t) counter64;
    if (counter == 0)
    {
        /* Fire it now. */
        counter = 1;
    }

    volatile uint32_t *this_lapic = get_per_cpu(lapic);

    lapic_write(this_lapic, LAPIC_TIMER_INITCNT, 0);

    lapic_write(this_lapic, LAPIC_TIMER_DIV, 3);
    lapic_write(this_lapic, LAPIC_LVT_TIMER, 34);
    lapic_write(this_lapic, LAPIC_TIMER_INITCNT, counter);
}

static bool should_use_tsc_deadline = false;

PER_CPU_VAR(bool defer_events);

void apic_set_oneshot(hrtime_t deadline)
{
    /* defer events is set in early boot so we don't fault trying to touch a
     * lapic mapping that doesn't exist
     */
    if (get_per_cpu(defer_events))
        return;

    if (should_use_tsc_deadline)
        apic_set_oneshot_tsc(deadline);
    else
        apic_set_oneshot_apic(deadline);
}

void apic_set_periodic(uint32_t period_ms, volatile uint32_t *lapic)
{
    uint32_t counter = apic_rate * period_ms;

    lapic_write(lapic, LAPIC_LVT_TIMER, 34 | LAPIC_LVT_TIMER_MODE_PERIODIC);
    lapic_write(lapic, LAPIC_TIMER_INITCNT, counter);
}

void apic_timer_set_periodic(hrtime_t period_ns)
{
    hrtime_t period_ms = period_ns / NS_PER_MS;
    uint32_t counter = apic_rate * period_ms;

    lapic_write(get_per_cpu(lapic), LAPIC_LVT_TIMER, 34 | LAPIC_LVT_TIMER_MODE_PERIODIC);
    lapic_write(get_per_cpu(lapic), LAPIC_TIMER_INITCNT, counter);
}

void platform_init_clockevents(void);

bool s = false;

void signal_stuff()
{
    s = true;
    printk("signaled\n");
}

int acpi_init_timer(void);

void apic_timer_init(void)
{
    driver_register_device(&apic_driver, &apic_timer_dev);

    /* Set the timer divisor to 16 */
    lapic_write(bsp_lapic, LAPIC_TIMER_DIV, 3);

    printf("apic: calculating APIC timer frequency\n");

    timer_calibrate();

    lapic_write(bsp_lapic, LAPIC_LVT_TIMER, LAPIC_TIMER_IVT_MASK);

    /* Initialize the APIC timer with IRQ2, periodic mode and an init count of
     * ticks_in_10ms/10(so we get a rate of 1000hz)
     */
    lapic_write(bsp_lapic, LAPIC_TIMER_DIV, 3);

    printf("apic: apic timer rate: %lu\n", apic_rate);
    us_apic_rate = INT_DIV_ROUND_CLOSEST(apic_rate, 1000);

    fp_32_64_div_32_32(&apic_ticks_per_ns, apic_rate, NS_PER_MS);

    DISABLE_INTERRUPTS();

    /* Install an IRQ handler for IRQ2 */

    assert(install_irq(2, apic_timer_irq, &apic_timer_dev, IRQ_FLAG_REGULAR, NULL) == 0);

    platform_init_clockevents();

    tsc_init();

#ifdef CONFIG_ACPI
    acpi_init_timer();
#endif

    ENABLE_INTERRUPTS();

    should_use_tsc_deadline = tsc_deadline_supported && get_main_clock() == &tsc_clock;
}

void apic_timer_smp_init(volatile uint32_t *lapic)
{
    /* Enable the local apic */
    lapic_write(lapic, LAPIC_SPUINT, 0x100 | APIC_DEFAULT_SPURIOUS_IRQ);

    /* Flush pending interrupts */
    lapic_write(lapic, LAPIC_EOI, 0);

    /* Set the task pri to 0 */
    lapic_write(lapic, LAPIC_TSKPRI, 0);

    /* Initialize the APIC timer with IRQ2, periodic mode and an init count of ticks_in_10ms/10(so
     * we get a rate of 1000hz)*/
    lapic_write(lapic, LAPIC_TIMER_DIV, 3);

    platform_init_clockevents();
}

void boot_send_ipi(uint8_t id, uint32_t type, uint32_t page)
{
    lapic_write(bsp_lapic, LAPIC_IPIID, (uint32_t) id << 24);
    uint64_t icr = type << 8 | (page & 0xff);
    icr |= (1 << 14);
    lapic_write(bsp_lapic, LAPIC_ICR, (uint32_t) icr);
}

PER_CPU_VAR(struct spinlock ipi_lock);

void apic_send_ipi(uint8_t id, uint32_t type, uint32_t page)
{
    struct spinlock *lock = get_per_cpu_ptr(ipi_lock);
    unsigned long cpu_flags = spin_lock_irqsave(lock);

    volatile uint32_t *this_lapic = get_per_cpu(lapic);

    if (unlikely(!this_lapic))
    {
        /* If we don't have a lapic yet, just return because we're in early boot
         * and we don't need that right now.
         */
        return;
    }

    while (lapic_read(this_lapic, LAPIC_ICR) & (1 << 12))
        cpu_relax();

    lapic_write(this_lapic, LAPIC_IPIID, (uint32_t) id << 24);
    uint64_t icr = type << 8 | (page & 0xff);
    icr |= (1 << 14);
    lapic_write(this_lapic, LAPIC_ICR, (uint32_t) icr);

    spin_unlock_irqrestore(lock, cpu_flags);
}

void apic_send_ipi_all(uint32_t type, uint32_t page)
{
    struct spinlock *lock = get_per_cpu_ptr(ipi_lock);
    unsigned long cpu_flags = spin_lock_irqsave(lock);

    volatile uint32_t *this_lapic = get_per_cpu(lapic);

    if (unlikely(!this_lapic))
    {
        /* If we don't have a lapic yet, just return because we're in early boot
         * and we don't need that right now.
         */
        return;
    }

    while (lapic_read(this_lapic, LAPIC_ICR) & (1 << 12))
        cpu_relax();

    uint64_t icr = 2 << 18 | type << 8 | (page & 0xff);
    icr |= (1 << 14);
    lapic_write(this_lapic, LAPIC_ICR, (uint32_t) icr);

    spin_unlock_irqrestore(lock, cpu_flags);
}

bool apic_send_sipi_and_wait(uint8_t lapicid, struct smp_header *s)
{
    boot_send_ipi(lapicid, ICR_DELIVERY_SIPI, 0);

    hrtime_t t0 = clocksource_get_time();
    while (clocksource_get_time() - t0 < 200 * NS_PER_MS)
    {
        if (s->boot_done == true)
        {
            return true;
        }
    }

    return false;
}

void apic_wake_up_processor(uint8_t lapicid, struct smp_header *s)
{
    boot_send_ipi(lapicid, ICR_DELIVERY_INIT, 0);

    hrtime_t t0 = clocksource_get_time();
    while (clocksource_get_time() - t0 < 10 * NS_PER_MS)
    {
        cpu_relax();
    }

    for (int i = 1; i < 3; i++)
    {
        bool success = apic_send_sipi_and_wait(lapicid, s);
        if (success)
            break;

        if (i != 2)
            printf("x86/wakeup: No response from AP(id %u)... retrying SIPI\n", lapicid);
    }

    if (!s->boot_done)
    {
        printf("x86/wakeup: Failed to start an AP with LAPICID %d\n", lapicid);
    }
}

void apic_set_irql(int irql)
{
    volatile uint32_t *this_lapic = get_per_cpu(lapic);
    lapic_write(this_lapic, LAPIC_TSKPRI, irql);
}

int apic_get_irql(void)
{
    volatile uint32_t *this_lapic = get_per_cpu(lapic);
    return (int) lapic_read(this_lapic, LAPIC_TSKPRI);
}

uint32_t apic_get_lapic_id(unsigned int cpu)
{
    return get_per_cpu_any(lapic_id, cpu);
}

volatile uint32_t *apic_get_lapic(unsigned int cpu)
{
    return get_per_cpu_any(lapic, cpu);
}

void lapic_init_per_cpu(void)
{
    uint64_t addr = rdmsr(IA32_APIC_BASE);
    addr &= 0xFFFFF000;
    /* Map the BSP's LAPIC */
    uintptr_t _lapic =
        (uintptr_t) mmiomap((void *) addr, PAGE_SIZE, VM_READ | VM_WRITE | VM_NOCACHE);
    assert(_lapic != 0);

    write_per_cpu(lapic, _lapic);

    apic_timer_smp_init(get_per_cpu(lapic));
}

void apic_set_lapic_id(unsigned int cpu, uint32_t __lapic_id)
{
    write_per_cpu_any(lapic_id, __lapic_id, cpu);
}

PER_CPU_VAR(bool timer_initialised);

/* Should be called percpu */
void platform_init_clockevents(void)
{
    struct timer *this_timer = get_per_cpu_ptr(lapic_timer);
    this_timer->set_oneshot = apic_set_oneshot;
    this_timer->set_periodic = apic_timer_set_periodic;

    this_timer->name = "lapic timer";

    write_per_cpu(timer_initialised, true);
    write_per_cpu(defer_events, false);

    if (this_timer->next_event)
    {
        this_timer->set_oneshot(this_timer->next_event);
    }
    else
    {
        this_timer->next_event = TIMER_NEXT_EVENT_NOT_PENDING;
        INIT_LIST_HEAD(&this_timer->event_list);
    }
}

struct timer *platform_get_timer(void)
{
    struct timer *this_timer = get_per_cpu_ptr(lapic_timer);

    if (!get_per_cpu(timer_initialised))
    {
        /* This is for clocksources that register themselves earlier than the platform timers */
        INIT_LIST_HEAD(&this_timer->event_list);
        this_timer->next_event = TIMER_NEXT_EVENT_NOT_PENDING;
        write_per_cpu(defer_events, true);
        write_per_cpu(timer_initialised, true);
        this_timer->set_oneshot = apic_set_oneshot;
        this_timer->set_periodic = apic_timer_set_periodic;
    }

    return this_timer;
}
