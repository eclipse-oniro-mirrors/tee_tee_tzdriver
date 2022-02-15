include $(LITEOSTOPDIR)/config.mk
MODULE_NAME := tzdriver

LOCAL_FLAGS += -fstack-protector-strong -Wno-unused-const-variable -Wno-unused-function
LOCAL_FLAGS += -DCONFIG_TZDRIVER=y
LOCAL_FLAGS += -DCONFIG_LITEOS_TZDRIVER=y
LOCAL_FLAGS += -DCONFIG_CPU_AFF_NR=1
LOCAL_FLAGS += -DCONFIG_KERNEL_CLIENT=y
LOCAL_FLAGS += -DCONFIG_PAGES_MEM=y
LOCAL_FLAGS += -DCONFIG_TEELOG=y
LOCAL_FLAGS += -DCONFIG_TEECD_PATH=\"/vendor/bin/teecd\"

LOCAL_FLAGS += -I.
LOCAL_FLAGS += -Iauth
LOCAL_FLAGS += -Icore
LOCAL_FLAGS += -Iinclude
LOCAL_FLAGS += -Itlogger
LOCAL_FLAGS += -I$(LITEOSTOPDIR)/../../third_party/mbedtls/include
LOCAL_FLAGS += -I$(LITEOSTOPDIR)/../../third_party/musl/porting/liteos_a/kernel
LOCAL_FLAGS += -I$(LITEOSTOPDIR)/../../device/hisilicon/hispark_taurus/sdk_liteos/board/include

LOCAL_SRCS  += los_adapt.c
LOCAL_SRCS  += core/agent.c
LOCAL_SRCS  += core/cmdmonitor.c
LOCAL_SRCS  += core/gp_ops.c
LOCAL_SRCS  += core/mailbox_mempool.c
LOCAL_SRCS  += core/mem.c
LOCAL_SRCS  += core/teek_client_api.c
LOCAL_SRCS  += core/session_manager.c
LOCAL_SRCS  += core/smc_smp.c
LOCAL_SRCS  += core/tc_client_driver.c
LOCAL_SRCS  += core/tzdebug.c
LOCAL_SRCS  += core/tz_spi_notify.c
LOCAL_SRCS  += tlogger/tlogger.c
LOCAL_SRCS  += tlogger/log_pages_cfg.c

include $(MODULE)
