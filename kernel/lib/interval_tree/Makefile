interval-tree-y:= interval_tree.o
interval-tree-$(CONFIG_KUNIT)+= interval_tree_test.o

obj-y+= $(patsubst %, lib/interval_tree/%, $(interval-tree-y))
