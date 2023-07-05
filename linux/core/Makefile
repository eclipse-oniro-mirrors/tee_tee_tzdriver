KERNEL_DIR :=$(srctree)

ifneq ($(TARGET_BUILD_VARIANT),user)
	ccflags-y += -DDEF_ENG
endif

EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../third_party/bounds_checking_function/include/
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/include
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/auth
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/tlogger
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/core
EXTRA_CFLAGS += -I$(KERNEL_DIR)/../../../../base/tee/tee_tzdriver/linux/kthread_affinity

obj-$(CONFIG_KERNEL_CLIENT) += teek_client_api.o
obj-y += smc_smp.o tc_client_driver.o session_manager.o mailbox_mempool.o teek_app_load.o
obj-y += agent.o gp_ops.o mem.o cmdmonitor.o tzdebug.o tz_spi_notify.o tz_pm.o tee_compat_check.o
obj-y += reserved_mempool.o
