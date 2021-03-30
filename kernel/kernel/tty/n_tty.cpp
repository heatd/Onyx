/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/tty.h>
#include <ctype.h>

#include <sys/ioctl.h>

static ssize_t n_tty_receive_input(char c, struct tty *tty);
static ssize_t n_tty_write_out(const char *s, size_t length, struct tty *tty);

const struct tty_ldisc_ops ntty_ops =
{
	n_tty_receive_input,
	n_tty_write_out
};

struct tty_line_disc ntty_disc = {.ldisc = N_TTY, .ops = &ntty_ops};
#define TTY_PRINT_IF_ECHO(c, l, t) if(t->term_io.c_lflag & ECHO) tty_write(c, l, t)

int iscntrl(int c)
{
	return (unsigned int) c < 0x20 || c == 0x7f || c == '\033';
}

struct tty_echo_args
{
	const char *to_echo;
	char inline_echo_buf[6];
	size_t len;
	bool ctl_echo_setup;
	bool do_not_print;
};

static inline bool should_print_special(char c)
{
	return c != '\t' && c != '\n' && c != '\021' && c != '\023' && c != '\x7f' && c != '\04';
}

void n_tty_receive_control_input(struct tty_echo_args *args, char c, struct tty *tty)
{
	if(c == TTY_CC(tty, VERASE))
	{
		if(tty->input_buf_pos <= 0)
		{
			args->to_echo = "";
			args->len = 0;
			tty->input_buf_pos = 0;
			return;
		}

		char old_char = tty->input_buf[tty->input_buf_pos - 1];

		tty->input_buf[tty->input_buf_pos - 1] = 0;
		tty->input_buf_pos--;
		args->to_echo = "\b \b";
		args->len = 3;

		if(TTY_LFLAG(tty, ECHOCTL) && iscntrl(old_char) && should_print_special(old_char))
		{
			args->to_echo = "\b \b\b \b";
			args->len = 6;
		}

		return;
	}

	if(TTY_LFLAG(tty, ECHOCTL) && should_print_special(c))
	{
		args->inline_echo_buf[0] = '^';
		args->inline_echo_buf[1] = c + 0x40;
		args->to_echo = args->inline_echo_buf;
		args->len = 2;
		args->ctl_echo_setup = true;
	}

	tty->input_buf[tty->input_buf_pos++] = c;

	if(c == TTY_CC(tty, VEOF))
		args->do_not_print = true;
}

static ssize_t n_tty_receive_input(char c, struct tty *tty)
{
	struct tty_echo_args args;
	args.to_echo = &c;
	args.len = 1; 
	args.ctl_echo_setup = false;
	args.do_not_print = false;

	spin_lock(&tty->input_lock);

	if(iscntrl(c) && TTY_LFLAG(tty, ICANON))
		n_tty_receive_control_input(&args, c, tty);
	else
	{
		tty->input_buf[tty->input_buf_pos++] = c;
	}

	if(!TTY_LFLAG(tty, ICANON) || c == '\n' || c == TTY_CC(tty, VEOF))
	{
		tty->line_ready = true;
		wait_queue_wake_all(&tty->read_queue);
	}

	spin_unlock(&tty->input_lock);

	if(TTY_LFLAG(tty, ECHO) && !args.do_not_print)
	{
		if(!iscntrl(c) || !should_print_special(c))
		{
			tty_write(args.to_echo, args.len, tty);
		}
		else if(args.ctl_echo_setup)
		{
			tty_write(args.to_echo, args.len, tty);
		}
	}

	return 0;
}

static ssize_t try_process_write(const char *s, size_t len, struct tty *tty)
{
	size_t i = 0;
	const char *buf = s;

	while(i < len)
	{
		char c = *s++;

		switch(c)
		{
			case '\n':
			{
				if(TTY_OFLAG(tty, ONLCR))
					goto write_and_process;
				break;
			}

			case '\r':
			{
				if(TTY_OFLAG(tty, OCRNL))
					goto write_and_process;
				break;
			}
		}

		i++;
	}

write_and_process:
	if(i != 0) tty->write(buf, i, tty);
	return i;
}

static void n_tty_output_char(char c, struct tty *tty)
{
	switch(c)
	{
		case '\n':
		{
			if(TTY_OFLAG(tty, ONLCR))
			{
				tty->write("\r\n", 2, tty);
				return;
			}

			break;
		}

		case '\r':
		{
			if(TTY_OFLAG(tty, OCRNL))
			{
				c = '\n';
				break;
			}

			/* TODO: ONOCR, OLCUC */
			break;
		}
	}

	tty->write(&c, 1, tty);
}

static ssize_t n_tty_write_out(const char *s, size_t length, struct tty *tty)
{
	size_t i = 0;
	while(i < length)
	{
		if(TTY_OFLAG(tty, OPOST))
		{
			/* Try and send the largest string of characters that don't need output */
			i += try_process_write(s + i, length - i, tty);

			if(i != length)
			{
				n_tty_output_char(*(s + i), tty);
				i++;
			}
		}
		else
			i += tty->write(s + i, length - i, tty);
	}

	return i;
}
