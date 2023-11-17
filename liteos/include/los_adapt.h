/*
 * los_adapt.h
 *
 * macros and interfaces for liteos tzdriver
 *
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef LOS_ADAPT_H
#define LOS_ADAPT_H

#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include "arm.h"
#include "fs/fs.h"
#include "fs_poll_pri.h"
#include "hisoc/random.h"
#include "los_process_pri.h"
#include "los_task.h"
#include "los_vm_lock.h"
#include "los_vm_map.h"
#include "los_vm_phys.h"
#include "mbedtls/sha256.h"

#define TEECD_UID 				97

#define VERIFY_READ 			0
#define VERIFY_WRITE 			1
#define MAX_DEV_NAME_SIZE  		32
#define SHA256_DIGEST_LENGTH 	32
#define ALIGN_TZ(x, boundary) (((x) + ((boundary) - 1)) & ~((boundary) - 1))

#define MISC_DYNAMIC_MINOR		255

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define LIBTEEC_SO "/vendor/lib/libteec_vendor.so"

struct miscdevice_adapt {
	int minor;
	char *name;
	const struct file_operations_vfs *op;
};

int misc_register_adapt(struct miscdevice_adapt *misc_device);

typedef pthread_mutex_t	 mutex_t;

#define MAX_PATH_SIZE	512

#ifndef IS_ERR_OR_NULL
#ifndef IS_ERR_VALUE
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long) - 4095)
#endif
#define IS_ERR_OR_NULL(x) ((!x) || IS_ERR_VALUE((uintptr_t)x))
#endif

#define TEE_DEV_PRI 0660

#define TASK_COMM_LEN OS_TCB_NAME_LEN

#define WQ_HIGHPRI (1 << 4)
#define IRQF_NO_SUSPEND		0x00004000
#define __GFP_ZERO 0x8000u

#define SZ_4K 0x1000UL
#define SZ_1M (1024 * 1024)
#define SZ_4M (4 * SZ_1M)
#define SZ_8M (8 * SZ_1M)

#define MAX_POW_TWO(n) \
( \
((n) >> 31) ? 31 : ((n) >> 30) ? 30 : \
((n) >> 29) ? 29 : ((n) >> 28) ? 28 : \
((n) >> 27) ? 27 : ((n) >> 26) ? 26 : \
((n) >> 25) ? 25 : ((n) >> 25) ? 25 : \
((n) >> 23) ? 23 : ((n) >> 22) ? 22 : \
((n) >> 21) ? 21 : ((n) >> 20) ? 20 : \
((n) >> 19) ? 19 : ((n) >> 18) ? 18 : \
((n) >> 17) ? 17 : ((n) >> 16) ? 16 : \
((n) >> 15) ? 15 : ((n) >> 14) ? 14 : \
((n) >> 13) ? 13 : ((n) >> 12) ? 12 : \
((n) >> 11) ? 11 : ((n) >> 10) ? 10 : \
((n) >> 9) ? 9: ((n) >> 8) ? 8 : \
((n) >> 7) ? 7: ((n) >> 6) ? 6 : \
((n) >> 5) ? 5: ((n) >> 4) ? 4 : \
((n) >> 3) ? 3: ((n) >> 2) ? 2 : 1)

#define GET_ORDER(n) \
( \
	n <= PAGE_SIZE ? 0 : (MAX_POW_TWO(n - 1) - PAGE_SHIFT + 1) \
)

#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC 1000
#endif

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC 1000000L
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC 1000000L
#endif

#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC 1000
#endif

#define CRASH_RET_EXIT 0
#define CRASH_RET_TA 1
#define CRASH_RET_IP 2

#define INIT_WORK_ONSTACK(_work, _func) \
do { \
	INIT_WORK(_work, _func); \
} while (0)

#define __WORK_INIT(n, f) { \
	.data = 0, \
	.entry = { &(n).entry, &(n).entry }, \
	.func = f \
}
#define DECLARE_WORK(work, func) \
	struct work_struct work = __WORK_INIT(work, func);

#define noinline __attribute__((noinline))

struct aes_param {
	unsigned char *iv;
	const unsigned char *key;
	int size;
	unsigned int encrypto_type;
};

bool schedule_work_on(int cpu, struct work_struct *work);
LosTaskCB *kthread_run(int (*threadfn)(uintptr_t data, int data_len), void *data, int len, char *name);
void kthread_stop(const LosTaskCB *k);
int kthread_should_stop(void);
int32_t do_vmalloc_remap(LosVmMapRegion *vma, void *kvaddr);
int remap_vmalloc_range(LosVmMapRegion *vma, void *addr, unsigned long pgoff);
int create_tc_client_device(const char *dev_name, const struct file_operations_vfs *op);
ssize_t simple_read_from_buffer(void *to, size_t count, const void *from, size_t available);
LosVmPage *mailbox_pool_alloc_pages(unsigned int order);
void mailbox_pool_free_pages(LosVmPage *page_array, size_t order);
char *get_process_path(LosTaskCB *task, char *tpath, int path_len);
int calc_task_so_hash(unsigned char *digest, uint32_t dig_len, LosTaskCB *cur_struct, int so_index);
int crypto_aescbckey256(unsigned char *output, const unsigned char *input, struct aes_param *param);

#define INT_SIZE 4

static inline struct workqueue_struct *alloc_ordered_workqueue(const char *fmt, unsigned int flags)
{
	return create_workqueue((char *)fmt);
}

static inline int access_ok(int type, unsigned long ptr, unsigned int size)
{
	if (ptr + size < ptr)
		return false;
	return LOS_IsUserAddress(ptr + size);
}

static inline int get_task_uid(LosTaskCB *task)
{
#ifdef LOSCFG_SECURITY_CAPABILITY
	int int_save = LOS_IntLock();
	int uid = -1;

	LosProcessCB *process = OS_PCB_FROM_PID(task->processID);
	if (process->user)
		uid = process->user->userID;
	LOS_IntRestore(int_save);
	return uid;
#else
	return 0;
#endif
}

static inline int devm_request_irq(unsigned int irq, irq_handler_t handler,
	unsigned long irq_flags, const char *devname, void *dev_id)
{
	return request_irq(irq, handler, irq_flags, devname, NULL);
}

static inline void *get_phy_page(void)
{
	LosVmPage *page = LOS_PhysPageAlloc();
	if (page == NULL)
		return NULL;
	return OsVmPageToVaddr(page);
}

static inline void *get_phy_pages(uint32_t size)
{
	void *page = LOS_PhysPagesAllocContiguous(ROUNDUP(size, PAGE_SIZE) >> PAGE_SHIFT);
	return page;
}

static inline void free_phy_page(void *ptr)
{
	if (ptr == NULL)
		return;
	LosVmPage *page = OsVmVaddrToPage(ptr);
	if (page != NULL)
		LOS_PhysPageFree(page);
}

static inline void kthread_bind_mask(LosTaskCB *p, UINT16 mask)
{
	if (p == NULL)
		return;
	LOS_TaskCpuAffiSet(p->taskID, mask);
}

static inline void preempt_disable(void)
{
	uint32_t int_save = LOS_IntLock();
	OsPercpuGet()->taskLockCnt++;
	LOS_IntRestore(int_save);
}

static inline void preempt_enable(void)
{
	uint32_t int_save = LOS_IntLock();
	OsPercpuGet()->taskLockCnt--;
	LOS_IntRestore(int_save);
}

static inline int cmpxchg(unsigned int *lock, int old, int new)
{
	return LOS_AtomicCmpXchg32bits((Atomic *)lock, new, old);
}

static inline int raw_smp_processor_id(void)
{
	return ArchCurrCpuid();
}

static inline int wake_up_process(LosTaskCB *p)
{
	LOS_TaskYield();
	return 0;
}

static inline void get_user(unsigned int *value, const unsigned int *user_ptr)
{
	copy_from_user(value, user_ptr, sizeof(unsigned int));
}

static inline int get_current_pid(void)
{
	return OsCurrTaskGet()->taskID;
}

/* unsupport restart syscall */
static inline int restart_syscall(void)
{
	return 0;
}

static inline LosTaskCB *get_process_group_leader(LosTaskCB *task)
{
	if (task == NULL)
		return NULL;
	return OS_TCB_FROM_TID(OS_PCB_FROM_PID(task->processID)->threadGroupID);
}

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
	if ((int)m < 0)
		return 0;

	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
}

static inline struct timespec current_kernel_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return ts;
}

static inline void init_deferrable_work(struct delayed_work *w, void(* wq)(struct work_struct *))
{
	INIT_DELAYED_WORK(w, wq);
}

static inline int is_kernel_thread(LosTaskCB *task)
{
	if (task == NULL)
		return true;
	return (OS_PCB_FROM_PID(task->processID)->processMode == OS_KERNEL_MODE);
}

static inline int is_teecd_process(LosTaskCB *teecd, LosTaskCB *task)
{
	if (teecd == NULL || task == NULL)
		return 0;
	return teecd->processID == task->processID;
}

typedef mbedtls_sha256_context tee_sha256_context;

static inline void init_tee_sha256(tee_sha256_context *ctx)
{
	mbedtls_sha256_init(ctx);
	(void)mbedtls_sha256_starts_ret(ctx, 0);
}

static inline void update_tee_sha256(tee_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
	(void)mbedtls_sha256_update_ret(ctx, input, ilen);
}

static inline void finish_tee_sha256(tee_sha256_context *ctx, unsigned char output[32])
{
	(void)mbedtls_sha256_finish_ret(ctx, output);
}

#undef kmalloc
#define kmalloc(size, flags) malloc(size)

#undef kzalloc
#define kzalloc(size, flags) calloc(1, size)

#undef kfree
#define kfree(ptr) free(ptr)

#define virt_to_phys(addr) LOS_PaddrQuery(addr)

#define phys_to_virt(addr) LOS_PaddrToKVaddr(addr)

#define virt_addr_valid(addr) LOS_PaddrQuery(addr)

#define __get_free_page(flags) get_phy_page()

#define __get_free_pages(flags, size) get_phy_pages(size)

#define free_pages(page, flags) free_phy_page(page)
#define __free_pages(page, flags) free_phy_page(page)
#define free_page(page) free_phy_page(page)

#define page_address(page) OsVmPageToVaddr(page)

#define __init

#endif
