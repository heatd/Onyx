uart8250-y:= drivers/serial/uart8250/uart8250.o
uart8250-$(CONFIG_ACPI)+= drivers/serial/uart8250/acpi.o
uart8250-$(CONFIG_DEVICE_TREE)+= drivers/serial/uart8250/devtree.o

obj-$(CONFIG_SERIAL_UART8250)+= $(uart8250-y)
