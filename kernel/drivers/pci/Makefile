pci-$(CONFIG_PCI):= $(patsubst %.cpp, %.o, $(wildcard drivers/pci/*.cpp)) \
		$(patsubst %.cpp, %.o, $(wildcard drivers/pci/legacy/*.cpp)) \

obj-y+= $(pci-y)
