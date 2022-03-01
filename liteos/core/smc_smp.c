/*
 * smc_smp.c
 *
 * function for sending smc cmd
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

#include "smc_smp.h"
#include <securec.h>
#include <linux/sched.h>
#include "agent.h"
#include "tc_ns_client.h"
#include "tc_ns_log.h"
#include "teek_client_constants.h"
#include "teek_ns_client.h"
#include "los_adapt.h"
#include "cmdmonitor.h"
#include "tlogger.h"

#define SECS_SUSPEND_STATUS      0xA5A5
#define PREEMPT_COUNT            10000
#define HZ_COUNT                 10
#define IDLED_COUNT              100
/*
 * when cannot find smc entry, will sleep 1ms
 * because the task will be killed in 25s if it not return,
 * so the retry count is 25s/1ms
 */
#define MAX_EMPTY_RUNS		   100
#define TZ_CPU_ZERO	0
#define TZ_CPU_ONE	 1
#define TZ_CPU_FOUR	4
#define TZ_CPU_FIVE	5
#define TZ_CPU_SIX	 6
#define TZ_CPU_SEVEN   7
#define LOW_BYTE    0xF

#define PENDING2_RETRY      (-1)

#define MAX_CHAR 0xff

/* Current state of the system */
static uint8_t g_sys_crash;

enum SPI_CLK_MODE {
	SPI_CLK_OFF = 0,
	SPI_CLK_ON,
};

typedef struct {
	int *n_idled;
	uint64_t *ret;
	uint64_t *exit_reason;
	uint64_t *ta;
	uint64_t *target;
} wo_pm_params;


struct shadow_work {
	struct work_struct work;
	uint64_t target;
};

unsigned long g_shadow_thread_id = 0;
static LosTaskCB *g_siq_thread = NULL;
static LosTaskCB *g_smc_svc_thread = NULL;
struct workqueue_struct *g_ipi_helper_worker = NULL;

enum cmd_reuse {
	CLEAR,	  /* clear this cmd index */
	RESEND,	 /* use this cmd index resend */
};

#ifdef CONFIG_DRM_ADAPT
static struct cpumask g_drm_cpu_mask;
static int g_drm_mask_flag = 0;
#endif

struct tc_ns_smc_queue *g_cmd_data;
paddr_t g_cmd_phys;

static struct list_head g_pending_head;
static spinlock_t g_pend_lock;

enum {
	TYPE_CRASH_TA  = 1,
	TYPE_CRASH_TEE = 2,
};

enum smc_ops_exit {
	SMC_OPS_NORMAL   = 0x0,
	SMC_OPS_SCHEDTO  = 0x1,
	SMC_OPS_START_SHADOW    = 0x2,
	SMC_OPS_START_FIQSHD    = 0x3,
	SMC_OPS_PROBE_ALIVE     = 0x4,
	SMC_OPS_ABORT_TASK      = 0x5,
	SMC_EXIT_NORMAL         = 0x0,
	SMC_EXIT_PREEMPTED      = 0x1,
	SMC_EXIT_SHADOW         = 0x2,
	SMC_EXIT_ABORT          = 0x3,
	SMC_EXIT_MAX            = 0x4,
};

#define SYM_NAME_LEN_MAX 16
#define SYM_NAME_LEN_1 7
#define SYM_NAME_LEN_2 4
#define CRASH_REG_NUM  3
#define LOW_FOUR_BITE  4

union crash_inf {
	uint64_t crash_reg[CRASH_REG_NUM];
	struct {
		uint8_t halt_reason : LOW_FOUR_BITE;
		uint8_t app : LOW_FOUR_BITE;
		char sym_name[SYM_NAME_LEN_1];
		uint16_t off;
		uint16_t size;
		uint32_t far;
		uint32_t fault;
		union {
			char sym_name_append[SYM_NAME_LEN_2];
			uint32_t elr;
		};
	} crash_msg;
};

struct tc_ns_smc_queue *get_cmd_data_buffer(void)
{
	return g_cmd_data;
}

static void acquire_smc_buf_lock(smc_buf_lock_t *lock)
{
	int ret;

	preempt_disable();
	do
		ret = cmpxchg(lock, 0, 1);
	while (ret);
}

static inline void release_smc_buf_lock(smc_buf_lock_t *lock)
{
	(void)cmpxchg(lock, 1, 0);
	preempt_enable();
}

static void occupy_setbit_smc_in_doing_entry(int32_t i, int32_t *idx)
{
	g_cmd_data->in[i].event_nr = i;
	ISB;
	DSB;
	set_bit(i, (unsigned long *)g_cmd_data->in_bitmap);
	set_bit(i, (unsigned long *)g_cmd_data->doing_bitmap);
	*idx = i;
}

static void occupy_clean_in_doing_entry(int32_t i)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	clear_bit(i, (unsigned long *)g_cmd_data->in_bitmap);
	clear_bit(i, (unsigned long *)g_cmd_data->doing_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static int occupy_free_smc_in_entry(const struct tc_ns_smc_cmd *cmd)
{
	int idx = -1;
	int i;

	if (!cmd) {
		tloge("bad parameters! cmd is NULL\n");
		return -1;
	}
	/*
	 * Note:
	 * acquire_smc_buf_lock will disable preempt and kernel will forbid
	 * call mutex_lock in preempt disabled scenes.
	 * To avoid such case(update_timestamp and update_chksum will call
	 * mutex_lock), only cmd copy is done when preempt is disable,
	 * then do update_timestamp and update_chksum.
	 * As soon as this idx of in_bitmap is set, gtask will see this
	 * cmd_in, but the cmd_in is not ready that lack of update_xxx,
	 * so we make a tricky here, set doing_bitmap and in_bitmap both
	 * at first, after update_xxx is done, clear doing_bitmap.
	 */
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	for (i = 0; i < MAX_SMC_CMD; i++) {
		if (test_bit(i, (unsigned long *)g_cmd_data->in_bitmap))
			continue;
		if (memcpy_s(&g_cmd_data->in[i], sizeof(g_cmd_data->in[i]),
			cmd, sizeof(*cmd)) != EOK) {
			tloge("memcpy failed,%s line:%d", __func__, __LINE__);
			break;
		}
		occupy_setbit_smc_in_doing_entry(i, &idx);
		break;
	}
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	if (idx == -1) {
		tloge("can't get any free smc entry\n");
		return -1;
	}

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	ISB;
	DSB;
	clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	return idx;
}

static int reuse_smc_in_entry(uint32_t idx)
{
	int rc = 0;

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (!(test_bit(idx, (unsigned long *)g_cmd_data->in_bitmap) &&
		test_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap))) {
		tloge("invalid cmd to reuse\n");
		rc = -1;
		goto out;
	}
	if (memcpy_s(&g_cmd_data->in[idx], sizeof(g_cmd_data->in[idx]),
		&g_cmd_data->out[idx], sizeof(g_cmd_data->out[idx]))) {
		tloge("memcpy failed,%s line:%d", __func__, __LINE__);
		rc = -1;
		goto out;
	}
	release_smc_buf_lock(&g_cmd_data->smc_lock);

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	ISB;
	DSB;
	clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
out:
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	return rc;
}

static int copy_smc_out_entry(uint32_t idx, struct tc_ns_smc_cmd *copy,
	enum cmd_reuse *usage)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (!test_bit(idx, (unsigned long *)g_cmd_data->out_bitmap)) {
		tloge("cmd out %u is not ready\n", idx);
		release_smc_buf_lock(&g_cmd_data->smc_lock);
		show_cmd_bitmap();
		return -ENOENT;
	}
	if (memcpy_s(copy, sizeof(*copy), &g_cmd_data->out[idx],
		sizeof(g_cmd_data->out[idx]))) {
		tloge("copy smc out failed\n");
		release_smc_buf_lock(&g_cmd_data->smc_lock);
		return -EFAULT;
	}

	ISB;
	DSB;
	if (g_cmd_data->out[idx].ret_val == TEEC_PENDING2 ||
		g_cmd_data->out[idx].ret_val == TEEC_PENDING) {
		*usage = RESEND;
	} else {
		clear_bit(idx, (unsigned long *)g_cmd_data->in_bitmap);
		clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
		*usage = CLEAR;
	}
	clear_bit(idx, (unsigned long *)g_cmd_data->out_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);

	return 0;
}

static inline void clear_smc_in_entry(uint32_t idx)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	clear_bit(idx, (unsigned long *)g_cmd_data->in_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static void release_smc_entry(uint32_t idx)
{
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	clear_bit(idx, (unsigned long *)g_cmd_data->in_bitmap);
	clear_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap);
	clear_bit(idx, (unsigned long *)g_cmd_data->out_bitmap);
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static bool is_cmd_working_done(uint32_t idx)
{
	bool ret = false;

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	if (test_bit(idx, (unsigned long *)g_cmd_data->out_bitmap))
		ret = true;
	release_smc_buf_lock(&g_cmd_data->smc_lock);
	return ret;
}

static void show_in_bitmap(int *cmd_in, uint32_t len)
{
	uint32_t idx;
	uint32_t in = 0;
	char bitmap[MAX_SMC_CMD + 1];

	if (len != MAX_SMC_CMD || !g_cmd_data)
		return;

	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (test_bit(idx, (unsigned long *)g_cmd_data->in_bitmap)) {
			bitmap[idx] = '1';
			cmd_in[in++] = idx;
		} else {
			bitmap[idx] = '0';
		}
	}
	bitmap[MAX_SMC_CMD] = '\0';
	tloge("in bitmap: %s\n", bitmap);
}

static void show_out_bitmap(int *cmd_out, uint32_t len)
{
	uint32_t idx;
	uint32_t out = 0;
	char bitmap[MAX_SMC_CMD + 1];

	if (len != MAX_SMC_CMD || !g_cmd_data)
		return;

	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (test_bit(idx, (unsigned long *)g_cmd_data->out_bitmap)) {
			bitmap[idx] = '1';
			cmd_out[out++] = idx;
		} else {
			bitmap[idx] = '0';
		}
	}
	bitmap[MAX_SMC_CMD] = '\0';
	tloge("out bitmap: %s\n", bitmap);
}

static void show_doing_bitmap(void)
{
	uint32_t idx;
	char bitmap[MAX_SMC_CMD + 1];

	if (!g_cmd_data)
		return;
	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (test_bit(idx, (unsigned long *)g_cmd_data->doing_bitmap))
			bitmap[idx] = '1';
		else
			bitmap[idx] = '0';
	}
	bitmap[MAX_SMC_CMD] = '\0';
	tloge("doing bitmap: %s\n", bitmap);
}

void show_cmd_bitmap_with_lock(void)
{
	if (g_cmd_data == NULL)
		return;
	acquire_smc_buf_lock(&g_cmd_data->smc_lock);
	show_cmd_bitmap();
	release_smc_buf_lock(&g_cmd_data->smc_lock);
}

static void show_single_cmd_info(const int *cmd, uint32_t len)
{
	uint32_t idx;

	if (len != MAX_SMC_CMD || !g_cmd_data)
		return;

	for (idx = 0; idx < MAX_SMC_CMD; idx++) {
		if (cmd[idx] == -1)
			break;
		tloge("cmd[%d]: cmd_id=%u, ca_pid=%u, dev_id = 0x%x, "
			"event_nr=%u, ret_val=0x%x\n",
			cmd[idx],
			g_cmd_data->in[cmd[idx]].cmd_id,
			g_cmd_data->in[cmd[idx]].ca_pid,
			g_cmd_data->in[cmd[idx]].dev_file_id,
			g_cmd_data->in[cmd[idx]].event_nr,
			g_cmd_data->in[cmd[idx]].ret_val);
	}
}

void show_cmd_bitmap(void)
{
	int *cmd_in = NULL;
	int *cmd_out = NULL;

	cmd_in = calloc(1, sizeof(int) * MAX_SMC_CMD);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)cmd_in)) {
		tloge("out of mem! cannot show in bitmap\n");
		return;
	}

	cmd_out = calloc(1, sizeof(int) * MAX_SMC_CMD);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)cmd_out)) {
		free(cmd_in);
		tloge("out of mem! cannot show out bitmap\n");
		return;
	}

	if (memset_s(cmd_in, sizeof(int)* MAX_SMC_CMD, MAX_CHAR, sizeof(int)* MAX_SMC_CMD) ||
		memset_s(cmd_out, sizeof(int)* MAX_SMC_CMD, MAX_CHAR, sizeof(int)* MAX_SMC_CMD)) {
		tloge("memset failed\n");
		goto error;
	}

	acquire_smc_buf_lock(&g_cmd_data->smc_lock);

	show_in_bitmap(cmd_in, MAX_SMC_CMD);
	show_doing_bitmap();
	show_out_bitmap(cmd_out, MAX_SMC_CMD);

	tloge("cmd in value:\n");
	show_single_cmd_info(cmd_in, MAX_SMC_CMD);

	tloge("cmd_out value:\n");
	show_single_cmd_info(cmd_out, MAX_SMC_CMD);

	release_smc_buf_lock(&g_cmd_data->smc_lock);

error:
	free(cmd_in);
	free(cmd_out);
}

static struct pending_entry *init_pending_entry(pid_t pid)
{
	struct pending_entry *pe = NULL;

	pe = calloc(1, sizeof(*pe));
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)pe)) {
		tloge("alloc pe failed\n");
		return NULL;
	}

	atomic_set(&pe->users, 1);
	pe->pid = pid;
	init_waitqueue_head(&pe->wq);
	atomic_set(&pe->run, 0);
	INIT_LIST_HEAD(&pe->list);
	spin_lock(&g_pend_lock);
	list_add_tail(&pe->list, &g_pending_head);
	spin_unlock(&g_pend_lock);

	return pe;
}

struct pending_entry *find_pending_entry(pid_t pid)
{
	struct pending_entry *pe = NULL;

	spin_lock(&g_pend_lock);
	list_for_each_entry(pe, &g_pending_head, list) {
		if (pe->pid == pid) {
			atomic_inc(&pe->users);
			spin_unlock(&g_pend_lock);
			return pe;
		}
	}
	spin_unlock(&g_pend_lock);
	return NULL;
}

void foreach_pending_entry(void (*func)(struct pending_entry *))
{
	struct pending_entry *pe = NULL;

	if (!func)
		return;

	spin_lock(&g_pend_lock);
	list_for_each_entry(pe, &g_pending_head, list)
		func(pe);
	spin_unlock(&g_pend_lock);
}

void put_pending_entry(struct pending_entry *pe)
{
	if (!pe)
		return;

	if (!atomic_dec_and_test(&pe->users))
		return;

	free(pe);
}

#ifdef CONFIG_TA_AFFINITY
static void restore_cpu_mask(struct pending_entry *pe)
{
	if (cpumask_equal(&pe->ca_mask, &pe->ta_mask))
		return;

	set_cpus_allowed_ptr(current, &pe->ca_mask);
}
#endif

static void release_pending_entry(struct pending_entry *pe)
{
#ifdef CONFIG_TA_AFFINITY
	restore_cpu_mask(pe);
#endif
	spin_lock(&g_pend_lock);
	list_del(&pe->list);
	spin_unlock(&g_pend_lock);
	put_pending_entry(pe);
}

static DECLARE_WAIT_QUEUE_HEAD(siq_th_wait);
static DECLARE_WAIT_QUEUE_HEAD(ipi_th_wait);
static atomic_t g_siq_th_run;

#define SHADOW_EXIT_RUN			 0x1234dead

/*
 * check ca and ta's affinity is match in 2 scene:
 * 1. when TA is blocked to REE
 * 2. when CA is wakeup by SPI wakeup
 * match_ta_affinity return true if affinity is changed
 */
#ifdef CONFIG_TA_AFFINITY
static bool match_ta_affinity(struct pending_entry *pe)
{
	if (!cpumask_equal(&current->cpus_allowed, &pe->ta_mask)) {
		if (set_cpus_allowed_ptr(current, &pe->ta_mask)) {
			tlogw("set %s affinity failed\n", current->comm);
			return false;
		}
		return true;
	}

	return false;
}
#else
static inline bool match_ta_affinity(struct pending_entry *pe)
{
	return false;
}
#endif

struct smc_cmd_ret {
	unsigned long exit;
	unsigned long ta;
	unsigned long target;
};

static inline void secret_fill(struct smc_cmd_ret *ret, uint64_t exit, uint64_t ta, uint64_t target)
{
	if (ret != NULL) {
		ret->exit = exit;
		ret->ta = ta;
		ret->target = target;
	}
}

bool sigkill_pending(LosTaskCB *tsk)
{
	if (!tsk) {
		tloge("tsk is null!\n");
		return 0;
	}

	return OsSigIsMember(&tsk->sig.sigwaitmask, SIGKILL) ||
		OsSigIsMember(&tsk->sig.sigwaitmask, SIGUSR1);
}

enum cmd_state {
	START,
	KILLING,
	KILLED,
};

#define CPU0_ONLY_MASK 0x0001

#if CONFIG_CPU_AFF_NR
static void set_cpu_strategy(UINT16 *old_mask)
{
	LosTaskCB *curr = OsCurrTaskGet();
	const UINT16 new_mask = CPU0_ONLY_MASK;

	*old_mask = curr->cpuAffiMask;
	kthread_bind_mask(curr, new_mask);
}
#endif

#if CONFIG_CPU_AFF_NR
static void restore_cpu(UINT16 *old_mask)
{
	LosTaskCB *curr = OsCurrTaskGet();
	kthread_bind_mask(curr, *old_mask);
}
#endif

struct smc_param {
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	struct smc_cmd_ret *secret;
	uint32_t cmd;
	uint64_t ca;
	uint32_t ta;
	uint32_t exit_reason;
	uint32_t target;
	enum cmd_state state;
	uint64_t ops;
};

static int do_smp_smc_send(struct smc_param *param)
{
	int ret;
	if (param->secret != NULL && param->secret->exit == SMC_EXIT_PREEMPTED) {
		param->r0 = param->cmd;
		if (param->state == KILLING) {
			param->state = KILLED;
			param->r1 = SMC_OPS_ABORT_TASK;
			param->r2 = param->ca;
		} else {
			param->r1 = SMC_OPS_SCHEDTO;
			param->r2 = param->ca;
			param->r3 = param->secret->ta;
			param->r4 = param->secret->target;
		}
	}
	int check_value = param->ops == SMC_OPS_SCHEDTO || param->ops == SMC_OPS_START_FIQSHD;
	if (param->secret != NULL && check_value)
		param->r4 = param->secret->target;
	ISB;
	DSB;

	do {
		__asm__ volatile(
			"mov r0, %[fid]\n"
			"mov r1, %[a1]\n"
			"mov r2, %[a2]\n"
			"mov r3, %[a3]\n"
			".arch_extension sec\n"
			"smc    #0\n"
			"str r0, [%[re0]]\n"
			"str r1, [%[re1]]\n"
			"str r2, [%[re2]]\n"
			"str r3, [%[re3]]\n"
			: [fid] "+r" (param->r0), [a1] "+r" (param->r1), [a2] "+r" (param->r2),
			[a3] "+r" (param->r3)
			: [re0] "r" (&ret), [re1] "r" (&param->exit_reason),
			[re2] "r" (&param->ta), [re3] "r" (&param->target)
			: "r0", "r1", "r2", "r3");
	} while (0);
	ISB;
	DSB;
	return ret;
}

static noinline int smp_smc_send(uint32_t cmd, unsigned long ops, unsigned long ca,
	struct smc_cmd_ret *secret, bool needKill)
{
	uint32_t ret = 0;
	bool check_value = false;
#if CONFIG_CPU_AFF_NR
	UINT16 old_mask;
#endif
	struct smc_param param;
	param.r0 = cmd;
	param.r1 = ops;
	param.r2 = ca;
	param.r3 = 0;
	param.r4 = 0;
	param.exit_reason = 0;
	param.ta = 0;
	param.target = 0;
	param.state = START;
	param.cmd = cmd;
	param.ca = ca;
	param.secret = secret;
	param.ops = ops;

RETRY:
#if CONFIG_CPU_AFF_NR
	set_cpu_strategy(&old_mask);
#endif

	ret = do_smp_smc_send(&param);

	if (secret == NULL)
		return ret;
	secret_fill(secret, param.exit_reason, param.ta, param.target);
	if (param.exit_reason == SMC_EXIT_PREEMPTED) {
		/* There's 2 ways to send a terminate cmd to kill a running TA,
		 * in current context or another. If send terminate in another
		 * context, may encounter concurrency problem, as terminate cmd
		 * is send but not process, the original cmd has finished.
		 * So we send the terminate cmd in current context.
		 */
		check_value = needKill && sigkill_pending(OsCurrTaskGet()) && param.state == START &&
			is_thread_reported(OsCurrTaskGet()->taskID);
		if (check_value == true) {
			param.state = KILLING;
			tloge("receive kill signal\n");
		}
#ifndef CONFIG_PREEMPT
		/* yield cpu to avoid soft lockup */
		cond_resched();
#endif
		goto RETRY;
	}
#if CONFIG_CPU_AFF_NR
	restore_cpu(&old_mask);
#endif
	return ret;
}

struct smc_in_params {
	unsigned long x0;
	unsigned long x1;
	unsigned long x2;
	unsigned long x3;
	unsigned long x4;
};

static uint32_t send_smc_cmd(uint32_t cmd, paddr_t cmd_addr,
	uint32_t cmd_type, uint8_t wait)
{
	struct smc_in_params in_param = { cmd, cmd_addr, cmd_type, 0 };
	uint32_t ret = 0;

	do {
		asm volatile(
			"mov r0, %[fid]\n"
			"mov r1, %[a1]\n"
			"mov r2, %[a2]\n"
			"mov r3, %[a3]\n"
			"mov r4, %[a4]\n"
			".arch_extension sec\n"
			"smc #0\n"
			"str r0, [%[re0]]\n" :
			[fid] "+r"(in_param.x0),
			[a1] "+r"(in_param.x1),
			[a2] "+r"(in_param.x2),
			[a3] "+r"(in_param.x3),
			[a4] "+r"(in_param.x0) :
			[re0] "r"(&ret) :
			"r0", "r1", "r2", "r3", "r4");
	} while (ret == TSP_REQUEST && wait);

	ISB;
	DSB;

	return ret;
}

int raw_smc_send(uint32_t cmd, paddr_t cmd_addr,
	uint32_t cmd_type, uint8_t wait)
{
	uint32_t r0;

#if (CONFIG_CPU_AFF_NR != 0)
	UINT16 old_mask;
	set_cpu_strategy(&old_mask);
#endif
	r0 = send_smc_cmd(cmd, cmd_addr, cmd_type, wait);
#if (CONFIG_CPU_AFF_NR != 0)
	restore_cpu(&old_mask);
#endif
	return r0;
}

void siq_dump(paddr_t mode)
{
	raw_smc_send(TSP_REE_SIQ, mode, 0, false);
	tz_log_write();
	do_cmd_need_archivelog();
}

static int siq_thread_fn(uintptr_t arg, int len)
{
	int ret;

	while (1) {
		ret = wait_event_interruptible(siq_th_wait,
			atomic_read(&g_siq_th_run));
		if (ret) {
			tloge("wait event interruptible failed!\n");
			return -EINTR;
		}
		atomic_set(&g_siq_th_run, 0);
		siq_dump((paddr_t)(1)); // set this addr to 1
	}
}

static void cmd_result_check(struct tc_ns_smc_cmd *cmd)
{
	bool check_value = false;
	check_value = cmd->ret_val == TEEC_PENDING ||
		cmd->ret_val == TEEC_PENDING2;

	if (check_value == true)
		tlogd("wakeup command %u\n", cmd->event_nr);
	if (cmd->ret_val == TEE_ERROR_TAGET_DEAD) {
		tloge("error smc call: ret = %x and cmd.err_origin=%x\n",
			  cmd->ret_val, cmd->err_origin);
#ifdef CONFIG_TEELOG
		cmd_monitor_ta_crash(TYPE_CRASH_TA);
#endif
	} else if (cmd->ret_val == TEE_ERROR_AUDIT_FAIL) {
		tloge("error smc call: ret = %x and cmd.err_origin=%x\n",
			cmd->ret_val, cmd->err_origin);
	}
}

static int shadow_wo_pm(const void *arg, const wo_pm_params *params)
{
	uint32_t r0 = TSP_REQUEST;
	uint32_t r1 = SMC_OPS_START_SHADOW;
	uint32_t r2 = OsCurrTaskGet()->taskID;
	uint32_t r3 = 0;
	uint32_t r4 = *(uint32_t *)arg;

	if (*(params->exit_reason) == SMC_EXIT_PREEMPTED) {
		r0 = TSP_REQUEST;
		r1 = SMC_OPS_SCHEDTO;
		r2 = OsCurrTaskGet()->taskID;
		r3 = *(params->ta);
		r4 = *(params->target);
	} else if (*(params->exit_reason) == SMC_EXIT_NORMAL) {
		r0 = TSP_REQUEST;
		r1 = SMC_OPS_SCHEDTO;
		r2 = OsCurrTaskGet()->taskID;
		r3 = 0;
		r4 = 0;
		if (*(params->n_idled) > IDLED_COUNT) {
			*(params->n_idled) = 0;
			r1 = SMC_OPS_PROBE_ALIVE;
		}
	}
	ISB;
	DSB;
	tlogd("%s: [cpu %d] r0=%x r1=%x r2=%x r3=%x r4=%x\n", __func__,
		raw_smp_processor_id(), r0, r1, r2, r3, r4);
	do {
		__asm__ volatile(
			"mov r0, %[fid]\n"
			"mov r1, %[a1]\n"
			"mov r2, %[a2]\n"
			"mov r3, %[a3]\n"
			"mov r4, %[a4]\n"
			".arch_extension sec\n"
			"smc #0\n"
			"str r0, [%[re0]]\n"
			"str r1, [%[re1]]\n"
			"str r2, [%[re2]]\n"
			"str r3, [%[re3]]\n"
			:[fid] "+r"(r0), [a1] "+r"(r1), [a2] "+r"(r2),
			[a3] "+r"(r3), [a4] "+r"(r4)
			:[re0] "r"(params->ret), [re1] "r"(params->exit_reason),
			[re2] "r"(params->ta), [re3] "r"(params->target)
			: "r0", "r1", "r2", "r3");
	} while (0);

	ISB;
	DSB;

	return 0;
}

static int check_shadow_param(uintptr_t arg, int len, struct pending_entry **pe)
{
	if (arg == 0)
		return -ENOMEM;
	if (len != sizeof(uint64_t)) {
		free((void *)arg);
		return -ENOMEM;
	}

	*pe = init_pending_entry(get_current_pid());
	if (*pe == NULL) {
		tloge("init pending entry failed\n");
		free((void *)arg);
		return -ENOMEM;
	}

	ISB;
	DSB;
	return 0;
}

static int shadow_thread_fn(uintptr_t arg, int len)
{
	uint64_t ret = 0;
	uint64_t exit_reason = SMC_EXIT_MAX;
	uint64_t ta = 0;
	uint64_t target = 0;
	int n_preempted = 0;
	int n_idled = 0;
	int ret_val;
	struct pending_entry *pe = NULL;
	int rc;
	wo_pm_params params = {&n_idled, &ret, &exit_reason, &ta, &target};

	ret = check_shadow_param(arg, len, &pe);
	if (ret)
		return ret;

RETRY_WO_PM:
	ret_val = shadow_wo_pm((void *)arg, &params);
	if (ret_val == -1)
		goto CLEAN_WO_PM;
	tlogd("shadow thread return %lld\n", exit_reason);
	if (exit_reason == SMC_EXIT_PREEMPTED) {
		n_idled = 0;
		if (++n_preempted > PREEMPT_COUNT) {
			tlogi("%s: retry 10K times on CPU%d\n", __func__, raw_smp_processor_id());
			n_preempted = 0;
		}
		goto RETRY_WO_PM;
	} else if (exit_reason == SMC_EXIT_NORMAL) {
		n_preempted = 0;
		long long timeout = HZ * (long)(HZ_COUNT + ((uint8_t)get_current_pid() & LOW_BYTE));
		rc = wait_event_interruptible_timeout(pe->wq, atomic_read(&pe->run), (long)timeout);
		if (!rc)
			n_idled++;
		if (atomic_read(&pe->run) == SHADOW_EXIT_RUN) {
			tlogd("shadow thread work quit, be killed\n");
			goto CLEAN_WO_PM;
		} else {
			atomic_set(&pe->run, 0);
			goto RETRY_WO_PM;
		}
	} else if (exit_reason == SMC_EXIT_SHADOW) {
		tlogd("shadow thread exit, it self\n");
	} else {
		tlogd("shadow thread exit with unknown code %ld\n", (long)exit_reason);
	}

CLEAN_WO_PM:
	free((void *)arg);
	release_pending_entry(pe);
	return ret_val;
}

static void shadow_work_func(struct work_struct *work)
{
	LosTaskCB *shadow_thread = NULL;
	if (work == NULL)
		return;
	struct shadow_work *s_work =
		container_of(work, struct shadow_work, work);
	uint64_t *target_arg = calloc(1, sizeof(uint64_t));

	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)target_arg)) {
		tloge("%s: kmalloc failed\n", __func__);
		return;
	}

	*target_arg = s_work->target;

	char shadow_name[OS_TCB_NAME_LEN] = {0};
	if (sprintf_s(shadow_name, OS_TCB_NAME_LEN, "shadow_th/%lu", g_shadow_thread_id++) < 0) {
		tloge("gen shadow name fail\n");
		free(target_arg);
		return;
	}
	shadow_thread = kthread_run(shadow_thread_fn, target_arg, sizeof(uint64_t), shadow_name);
	if (IS_ERR_OR_NULL(shadow_thread)) {
		free(target_arg);
		tloge("couldn't create shadow_thread %ld\n",
			PTR_ERR(shadow_thread));
		return;
	}
	tlogd("%s: create shadow thread %lu for target %llx\n",
		__func__, g_shadow_thread_id, *target_arg);
	wake_up_process(shadow_thread);
}

static int proc_smc_wakeup_ca(pid_t ca, int which)
{
	if (ca == 0) {
		tlogw("wakeup for ca = 0\n");
	} else {
		struct pending_entry *pe = find_pending_entry(ca);

		if (pe == NULL) {
			tloge("invalid ca pid=%d for pending entry\n", (int)ca);
			return -1;
		}
		atomic_set(&pe->run, which);
		wake_up(&pe->wq);
		tlogd("wakeup pending thread %ld\n", (long)ca);
		put_pending_entry(pe);
	}
	return 0;
}

void wakeup_pe(struct pending_entry *pe)
{
	if (pe != NULL) {
		atomic_set(&pe->run, 1);
		wake_up(&pe->wq);
	}
}

int smc_wakeup_broadcast(void)
{
	foreach_pending_entry(wakeup_pe);
	return 0;
}

int smc_wakeup_ca(pid_t ca)
{
	return proc_smc_wakeup_ca(ca, 1); // set pe->run to 1
}

int smc_shadow_exit(pid_t ca)
{
	return proc_smc_wakeup_ca(ca, SHADOW_EXIT_RUN);
}

void fiq_shadow_work_func(uint64_t target)
{
	struct smc_cmd_ret secret = { SMC_EXIT_MAX, 0, target };

	smp_smc_send(TSP_REQUEST, (unsigned long)SMC_OPS_START_FIQSHD,
		(unsigned long)get_current_pid(), &secret, false);

	return;
}

int smc_queue_shadow_worker(uint64_t target)
{
	struct shadow_work shadow_work;
	INIT_WORK_ONSTACK(&shadow_work.work, shadow_work_func);
	shadow_work.target = target;

	/* Run work on CPU 0 */
	queue_work(g_ipi_helper_worker, &shadow_work.work);
	flush_work(&shadow_work.work);
	return 0;
}

#ifdef CONFIG_DRM_ADAPT
static void set_drm_strategy(void)
{
	if (!g_drm_mask_flag) {
		cpumask_clear(&g_drm_cpu_mask);
		cpumask_set_cpu(CPU_FOUR, &g_drm_cpu_mask);
		cpumask_set_cpu(CPU_FIVE, &g_drm_cpu_mask);
		cpumask_set_cpu(CPU_SIX, &g_drm_cpu_mask);
		cpumask_set_cpu(CPU_SEVEN, &g_drm_cpu_mask);
		g_drm_mask_flag = 1;
	}

	if (current->group_leader &&
		strstr(current->group_leader->comm, "drm@1.")) {
		set_cpus_allowed_ptr(current, &g_drm_cpu_mask);
		set_user_nice(current, DRM_USR_PRIOR);
	}
}
#endif

static int smc_ops_normal(enum cmd_reuse *cmd_usage, int *cmd_index,
	int *last_index, const struct tc_ns_smc_cmd *cmd, uint64_t ops)
{
	if (ops != SMC_OPS_NORMAL)
		return 0;

	if (*cmd_usage == RESEND) {
		if (reuse_smc_in_entry(*cmd_index)) {
			tloge("reuse smc entry failed\n");
			release_smc_entry(*cmd_index);
			return -ENOMEM;
		}
	} else {
		*cmd_index = occupy_free_smc_in_entry(cmd);
		if (*cmd_index == -1) {
			tloge("there's no more smc entry\n");
			return -ENOMEM;
		}
	}

	if (*cmd_usage != CLEAR) {
		*cmd_index = *last_index;
		*cmd_usage = CLEAR;
	} else {
		*last_index = *cmd_index;
	}

	tlogd("submit new cmd: cmd.ca=%u cmd-id=%x ev-nr=%u "
		"cmd-index=%u last-index=%d\n",
		cmd->ca_pid, cmd->cmd_id,
		g_cmd_data->in[*cmd_index].event_nr, *cmd_index,
		*last_index);
	return 0;
}

static int smp_smc_send_cmd_done(int cmd_index, struct tc_ns_smc_cmd *cmd,
	struct tc_ns_smc_cmd *in)
{
	cmd_result_check(cmd);
	switch (cmd->ret_val) {
	case TEEC_PENDING2: {
		unsigned int agent_id = cmd->agent_id;
		/* If the agent does not exist post
		 * the answer right back to the TEE
		 */
		if (agent_process_work(cmd, agent_id))
			tloge("agent process work failed\n");
		return PENDING2_RETRY;
	}
	case TEE_ERROR_TAGET_DEAD:
	case TEEC_PENDING:
	/* just copy out, and let out to proceed */
	default:
		if (memcpy_s(in, sizeof(*in), cmd, sizeof(*cmd))) {
			tloge("memcpy failed,%s line:%d", __func__, __LINE__);
			cmd->ret_val = -1;
		}

		break;
	}

	return 0;
}

#define KERNEL_INDEX 5
static void print_crash_msg(union crash_inf *crash_info)
{
	static const char *tee_critical_app[] = {
		"gtask",
		"teesmcmgr",
		"hmsysmgr",
		"hmfilemgr",
		"platdrv",
		"kernel", /* index must be same with KERNEL_INDEX */
		"vltmm_service",
		"tee_drv_server"
	};
	int app_num = sizeof(tee_critical_app) / sizeof(tee_critical_app[0]);
	const char *crash_app_name = "NULL";
	uint16_t off = crash_info->crash_msg.off;
	int app_index = crash_info->crash_msg.app & LOW_BYTE;
	int halt_reason = crash_info->crash_msg.halt_reason;

	crash_info->crash_msg.off = 0;

	if (app_index >= 0 && app_index < app_num)
		crash_app_name = tee_critical_app[app_index];
	else
		tloge("index error: %x\n", crash_info->crash_msg.app);

	if (app_index == KERNEL_INDEX) {
		tloge("====crash app:%s user sym:%s kernel crash off/size: "
			"<0x%x/0x%x>\n", crash_app_name,
			crash_info->crash_msg.sym_name,
			off, crash_info->crash_msg.size);
		tloge("====crash halt reason: 0x%x far:0x%x fault:0x%x "
			"elr:0x%x (ret_ip: 0x%llx)\n",
			halt_reason, crash_info->crash_msg.far,
			crash_info->crash_msg.fault, crash_info->crash_msg.elr,
			crash_info->crash_reg[2]);
	} else {
		char syms[SYM_NAME_LEN_MAX] = {0};

		if (memcpy_s(syms, SYM_NAME_LEN_MAX,
			crash_info->crash_msg.sym_name, SYM_NAME_LEN_1))
			tloge("memcpy sym name failed!\n");

		if (memcpy_s(syms + SYM_NAME_LEN_1,
			SYM_NAME_LEN_MAX - SYM_NAME_LEN_1,
			crash_info->crash_msg.sym_name_append, SYM_NAME_LEN_2))
			tloge("memcpy sym_name_append failed!\n");
		tloge("====crash app:%s user_sym:%s + <0x%x/0x%x>\n",
		      crash_app_name, syms, off, crash_info->crash_msg.size);
		tloge("====crash far:0x%x fault:%x\n",
		      crash_info->crash_msg.far, crash_info->crash_msg.fault);
	}
}

static int smp_smc_send_process(struct tc_ns_smc_cmd *cmd, uint64_t ops,
	struct smc_cmd_ret *cmd_ret, int cmd_index)
{
	int ret;

	tlogd("smc send start cmd_id = %u, ca = %u\n",
		cmd->cmd_id, cmd->ca_pid);

	ret = smp_smc_send(TSP_REQUEST, (unsigned long)ops,
		(unsigned long)get_current_pid(), cmd_ret, ops != SMC_OPS_ABORT_TASK);

	tlogd("smc send ret = %x, cmd ret.exit=%ld, cmd index=%d\n",
		ret, (long)cmd_ret->exit, cmd_index);
	ISB;
	DSB;
	if (ret == (int)TSP_CRASH) {
		union crash_inf crash_info;
		crash_info.crash_reg[0] = cmd_ret->exit;
		crash_info.crash_reg[1] = cmd_ret->ta;
		crash_info.crash_reg[2] = cmd_ret->target;

		tloge("TEEOS has crashed!\n");
		print_crash_msg(&crash_info);

		g_sys_crash = 1;
		cmd_monitor_ta_crash(TYPE_CRASH_TEE);

		cmd->ret_val = -1;
		return -1;
	}

	return 0;
}

static int init_for_smc_send(struct tc_ns_smc_cmd *in,
	struct pending_entry **pe, struct tc_ns_smc_cmd *cmd,
	bool reuse)
{
#ifdef CONFIG_DRM_ADAPT
	set_drm_strategy();
#endif
	*pe = init_pending_entry(get_current_pid());
	if (!(*pe)) {
		tloge("init pending entry failed\n");
		return -ENOMEM;
	}

	in->ca_pid = get_current_pid();
	if (reuse)
		return 0;

	if (memcpy_s(cmd, sizeof(*cmd), in, sizeof(*in))) {
		tloge("memcpy in cmd failed\n");
		release_pending_entry(*pe);
		return -EFAULT;
	}

	return 0;
}

#define GOTO_RESLEEP 1
#define GOTO_RETRY_WITH_CMD 2
#define GOTO_RETRY 3
#define GOTO_CLEAN 4

static int check_is_ca_killed(int cmd_index, uint64_t *ops)
{
	/* if CA has not been killed */
	if (!sigkill_pending(OsCurrTaskGet())) {
		if (!is_cmd_working_done(cmd_index)) {
			return GOTO_RESLEEP;
		} else {
			tloge("cmd done, may miss a spi!\n");
			show_cmd_bitmap_with_lock();
		}
	} else {
		/* if CA killed, send terminate cmd */
		*ops = SMC_OPS_ABORT_TASK;
		tloge("CA is killed, send terminate!\n");
		return GOTO_RETRY_WITH_CMD;
	}
	return 0;
}

struct cmd_pram {
	struct tc_ns_smc_cmd *cmd;
	int cmd_index;
	enum cmd_reuse *cmd_usage;
};

static int cmd_done_process(struct tc_ns_smc_cmd *in, struct cmd_pram *c_param, uint64_t *ops)
{
	if ((in == NULL) || (c_param == NULL) || (ops == NULL))
		return 0;

	if (copy_smc_out_entry(c_param->cmd_index, c_param->cmd, c_param->cmd_usage)) {
		c_param->cmd->ret_val = -1;
		return GOTO_CLEAN;
	}

	if (smp_smc_send_cmd_done(c_param->cmd_index, c_param->cmd, in) == -1) {
		*ops = SMC_OPS_NORMAL;
		/* cmd will be reused */
		return GOTO_RETRY;
	}

	return 0;
}

static int retry_with_fill_cmd_process(struct tc_ns_smc_cmd *in, struct cmd_pram *c_param, struct pending_entry *pe,
	uint64_t *ops)
{
	struct smc_cmd_ret cmd_ret = {0};

	if ((in == NULL) || (c_param == NULL) || (pe == NULL) || (ops == NULL))
		return 0;

	while (1) {
		if (smp_smc_send_process(c_param->cmd, *ops, &cmd_ret, c_param->cmd_index) == -1)
			return GOTO_CLEAN;
		if (is_cmd_working_done(c_param->cmd_index))
			return cmd_done_process(in, c_param, ops);

		if (cmd_ret.exit != SMC_EXIT_NORMAL) {
			tloge("invalid cmd work state\n");
			c_param->cmd->ret_val = -1;
			return GOTO_CLEAN;
		}
		/* task pending exit */
		tlogd("goto sleep, exit_reason=%lld\n", cmd_ret.exit);
RESLEEP:
		if (wait_event_interruptible_timeout(pe->wq, atomic_read(&pe->run),
			(long)(RESLEEP_TIMEOUT * HZ)) == 0) {
			tlogd("CA wait event for %d s\n", RESLEEP_TIMEOUT);
			int ret = check_is_ca_killed(c_param->cmd_index, ops);
			if (ret == GOTO_RESLEEP)
				goto RESLEEP;
			else if (ret == GOTO_RETRY_WITH_CMD)
				continue;
		}
		atomic_set(&pe->run, 0);
		if (is_cmd_working_done(c_param->cmd_index)) {
			tlogd("cmd is done\n");
			return cmd_done_process(in, c_param, ops);
		}
		*ops = SMC_OPS_SCHEDTO;
	}

	return 0;
}

static int smp_smc_send_func(struct tc_ns_smc_cmd *in, bool reuse)
{
	int cmd_index = 0;
	int last_index = 0;
	struct tc_ns_smc_cmd cmd = { {0}, 0 };
	struct pending_entry *pe = NULL;
	uint64_t ops;
	enum cmd_reuse cmd_usage = CLEAR;

	int ret;
	bool check = false;

	if (init_for_smc_send(in, &pe, &cmd, reuse))
		return TEEC_ERROR_GENERIC;
	if (reuse) {
		last_index = in->event_nr;
		cmd_index = in->event_nr;
		cmd_usage = RESEND;
	}
	ops = SMC_OPS_NORMAL;

retry:
	if (smc_ops_normal(&cmd_usage, &cmd_index, &last_index, &cmd, ops)) {
		release_pending_entry(pe);
		return TEEC_ERROR_GENERIC;
	}

	struct cmd_pram c_param;
	c_param.cmd = &cmd;
	c_param.cmd_index = cmd_index;
	c_param.cmd_usage = &cmd_usage;

	ret = retry_with_fill_cmd_process(in, &c_param, pe, &ops);
	if (ret == GOTO_CLEAN)
		goto clean;
	else if (ret == GOTO_RETRY)
		goto retry;

clean:
	check = (cmd_usage != CLEAR && cmd.ret_val != TEEC_PENDING);
	if (check == true)
		release_smc_entry(cmd_index);
	release_pending_entry(pe);
	return cmd.ret_val;
}

static int smc_svc_thread_fn(uintptr_t arg, int len)
{
	while (!kthread_should_stop()) {
		struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
		int ret;

		smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
		smc_cmd.cmd_id = GLOBAL_CMD_ID_SET_SERVE_CMD;
		ret = smp_smc_send_func(&smc_cmd, false);
		tlogd("smc svc return 0x%x\n", ret);
	}
	tloge("smc svc thread stop\n");
	return 0;
}

void wakeup_tc_siq(void)
{
	atomic_set(&g_siq_th_run, 1);
	wake_up_interruptible(&siq_th_wait);
}

/*
 * This function first power on crypto cell, then send smc cmd to trustedcore.
 * After finished, power off crypto cell.
 */
static int proc_tc_ns_smc(struct tc_ns_smc_cmd *cmd, bool reuse)
{
	int ret;
	struct cmd_monitor *item = NULL;

	if (g_sys_crash) {
		tloge("ERROR: sys crash happened!!!\n");
		return TEEC_ERROR_GENERIC;
	}
	if (!cmd) {
		tloge("invalid cmd\n");
		return TEEC_ERROR_GENERIC;
	}
	tlogd(KERN_INFO "***smc call start on cpu %d ***\n",
		raw_smp_processor_id());

	item = cmd_monitor_log(cmd);
	ret = smp_smc_send_func(cmd, reuse);
	cmd_monitor_logend(item);

	return ret;
}

int tc_ns_smc(struct tc_ns_smc_cmd *cmd)
{
	return proc_tc_ns_smc(cmd, false);
}

int tc_ns_smc_with_no_nr(struct tc_ns_smc_cmd *cmd)
{
	return proc_tc_ns_smc(cmd, true);
}

static void smc_work_no_wait(uint32_t type)
{
	raw_smc_send(TSP_REQUEST, g_cmd_phys, type, true);
}

static void smc_work_set_cmd_buffer(struct work_struct *work)
{
	(void)work;
	smc_work_no_wait(TC_NS_CMD_TYPE_SECURE_CONFIG);
}

static void smc_set_cmd_buffer(void)
{
	struct work_struct work;

	INIT_WORK_ONSTACK(&work, smc_work_set_cmd_buffer);
	/* Run work on CPU 0 */
	schedule_work_on(0, &work);
	flush_work(&work);
}

static int alloc_cmd_buffer(void)
{
	g_cmd_data = (struct tc_ns_smc_queue *)__get_free_page();
	if (!g_cmd_data)
		return -ENOMEM;
	if (memset_s(g_cmd_data, sizeof(struct tc_ns_smc_queue), 0, sizeof(struct tc_ns_smc_queue))) {
		free_page(g_cmd_data);
		g_cmd_data = NULL;
		return -ENOMEM;
	}
	g_cmd_phys = LOS_PaddrQuery(g_cmd_data);
	return 0;
}

static int init_smc_related_rsrc(void)
{
	g_ipi_helper_worker = create_workqueue("ipihelper");
	if (g_ipi_helper_worker == NULL) {
		tloge("couldn't create workqueue.\n");
		return -ENOMEM;
	}

	wake_up_process(g_siq_thread);
	init_cmd_monitor();
	INIT_LIST_HEAD(&g_pending_head);
	spin_lock_init(&g_pend_lock);

	return 0;
}

int smc_context_init(void)
{
	int ret;

	ret = alloc_cmd_buffer();
	if (ret)
		return ret;

	/* Send the allocated buffer to TrustedCore for init */
	smc_set_cmd_buffer();

	g_siq_thread = kthread_run(siq_thread_fn, NULL, 0, "siqthread/0");
	if (unlikely(IS_ERR_OR_NULL(g_siq_thread))) {
		pr_err("couldn't create siqthread %ld\n",
			PTR_ERR(g_siq_thread));
		ret = (int)PTR_ERR(g_siq_thread);
		goto free_mem;
	}

	ret = init_smc_related_rsrc();
	if (ret)
		goto free_siq_worker;

	return 0;

free_siq_worker:
	kthread_stop(g_siq_thread);
	g_siq_thread = NULL;
free_mem:
	free_page(g_cmd_data);
	g_cmd_data = NULL;
	return ret;
}

int init_smc_svc_thread(void)
{
	g_smc_svc_thread = kthread_run(smc_svc_thread_fn, NULL,
		0, "smc_svc_thread");
	if (unlikely(IS_ERR_OR_NULL(g_smc_svc_thread))) {
		tloge("couldn't create smc_svc_thread %ld\n",
			PTR_ERR(g_smc_svc_thread));
		return PTR_ERR(g_smc_svc_thread);
	}
	wake_up_process(g_smc_svc_thread);
	return 0;
}

void smc_free_data(void)
{
	free_page(g_cmd_data);
	g_cmd_data = NULL;
	if (!IS_ERR_OR_NULL(g_smc_svc_thread)) {
		kthread_stop(g_smc_svc_thread);
		g_smc_svc_thread = NULL;
	}
}

