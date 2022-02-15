ifeq ($(strip $(TARGET_PRODUCT)), mdc)
	ccflags-y += -DCONFIG_MDC_PLATFORM
endif

ifeq ($(strip $(TARGET_PRODUCT)), mini)
	ccflags-y += -DCONFIG_MINI_PLATFORM
endif

KERNEL_DIR :=$(srctree)

ifneq ($(TARGET_BUILD_VARIANT),user)
	ccflags-y += -DDEF_ENG
endif

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../third_party/bounds_checking_function/include/
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../base/tee/tee_tzdriver/linux/include
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../../base/tee/tee_tzdriver/linux/core

obj-$(CONFIG_TEELOG) += tlogger.o

# If no log mechanism is available, the pages memory can be used.
obj-$(CONFIG_PAGES_MEM) += log_pages_cfg.o
