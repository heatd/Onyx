binary-search-tree-y:= binary_search_tree.o
binary-search-tree-$(CONFIG_KUNIT)+= augmented-test.o

obj-y+= $(patsubst %, lib/binary_search_tree/%, $(binary-search-tree-y))
