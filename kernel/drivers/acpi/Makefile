acpi-y:= acpi_osl.o acpi.o

obj-$(CONFIG_ACPI)+= $(patsubst %, drivers/acpi/%, $(acpi-y))

include drivers/acpi/acpica/Makefile
