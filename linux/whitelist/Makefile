KERNEL_DIR := $(srctree)

ifneq ($(TARGET_BUILD_VARIANT), user)
	ccflags-y += -DDEF_ENG
endif

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../third_party/bounds_checking_function/include
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/include
EXTRA_CFLAGS += -include internal_functions.h

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/core

obj-y += agent_allowed_ca.o