usb-y:= $(patsubst %.cpp, %.o, $(wildcard drivers/usb/*.cpp)) \
	$(patsubst %.cpp, %.o, $(wildcard drivers/usb/ehci/*.cpp))

obj-$(CONFIG_USB)+= $(usb-y)

module-name:= usb