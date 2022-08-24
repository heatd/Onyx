zstd_decompress-y := \
	zstd/lib/common/debug.o \
	zstd/lib/common/xxhash.o \
	zstd/lib/common/entropy_common.o \
	zstd/lib/common/error_private.o \
	zstd/lib/common/fse_decompress.o \
	zstd/lib/common/zstd_common.o \
	zstd/lib/decompress/huf_decompress.o \
	zstd/lib/decompress/zstd_ddict.o \
	zstd/lib/decompress/zstd_decompress.o \
	zstd/lib/decompress/zstd_decompress_block.o \
	module.o

ZSTD_SUFF:=

ifeq ($(CONFIG_ZSTD_NO_KASAN), y)
ZSTD_SUFF:=_NOKASAN
endif

obj-$(CONFIG_ZSTD)$(ZSTD_SUFF)+= $(patsubst %, lib/zstd/%, $(zstd_decompress-$(CONFIG_ZSTD)))
