ifeq ($(CONFIG_TZDRIVER),y)
KERNEL_DIR := $(srctree)

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../third_party/bounds_checking_function/include/
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../base/tee/tee_tzdriver/linux/include/

obj-$(CONFIG_TZDRIVER) += auth/
obj-$(CONFIG_TZDRIVER) += core/
obj-$(CONFIG_TZDRIVER) += tlogger/

endif
