KERNEL_DIR :=$(srctree)

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../third_party/bounds_checking_function/include/
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../base/tee/tee_tzdriver/linux/include
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../base/tee/tee_tzdriver/linux/core
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../base/tee/tee_tzdriver/linux/tlogger

obj-$(CONFIG_CLIENT_AUTH) += client_hash_auth.o

ifeq ($(CONFIG_CLIENT_AUTH), y)
	obj-y += auth_base_impl.o
endif
