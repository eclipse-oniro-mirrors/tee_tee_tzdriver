/*
 * smc_smp.h
 *
 * function declaration for sending smc cmd
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
#ifndef SMC_SMP_H
#define SMC_SMP_H

#include "teek_client_constants.h"
#include "teek_ns_client.h"

enum tc_ns_cmd_type {
	TC_NS_CMD_TYPE_INVALID = 0,
	TC_NS_CMD_TYPE_NS_TO_SECURE,
	TC_NS_CMD_TYPE_SECURE_TO_NS,
	TC_NS_CMD_TYPE_SECURE_TO_SECURE,
	TC_NS_CMD_TYPE_SECURE_CONFIG = 0xf,
	TC_NS_CMD_TYPE_MAX
};

struct pending_entry {
	atomic_t users;
	struct task_struct *task;
	pid_t pid;
	wait_queue_head_t wq;
	atomic_t run;
	struct list_head list;
};

#define MAX_SMC_CMD 18

#ifdef DIV_ROUND_UP
#undef DIV_ROUND_UP
#endif
#define DIV_ROUND_UP(n, d)			  (((n) + (d) - 1) / (d))

#define BITS_PER_BYTE				   8

#ifdef BITS_TO_LONGS
#undef BITS_TO_LONGS
#endif
#define BITS_TO_LONGS(nr)			   DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(uint64_t))

#ifdef BIT_MASK
#undef BIT_MASK
#endif
#define BIT_MASK(nr)					(1UL << (((uint64_t)nr) % sizeof(uint64_t)))

#ifdef BIT_WORD
#undef BIT_WORD
#endif
#define BIT_WORD(nr)					((nr) / sizeof(uint64_t))

#ifdef DECLARE_BITMAP
#undef DECLARE_BITMAP
#endif
#define DECLARE_BITMAP(name, bits)	  uint64_t name[BITS_TO_LONGS(bits)]

static inline void set_bit(int nr, volatile unsigned long *addr)
{
	if (addr == NULL)
		return;
	const unsigned long mask = BIT_MASK(nr);
	unsigned long *p   = ((unsigned long *)addr) + BIT_WORD(nr);
	*p |= mask;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	if (addr == NULL)
		return;

	const unsigned long mask = BIT_MASK(nr);
	unsigned long *p   = ((unsigned long *)addr) + BIT_WORD(nr);
	*p &= ~mask;
}

static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	if (addr == NULL)
		return 0;

	return 1UL & (addr[BIT_WORD(nr)] >> ((unsigned int)nr & (BITS_PER_BYTE * sizeof(uint64_t) - 1)));
}

typedef uint32_t smc_buf_lock_t;

struct tc_ns_smc_queue {
	/* set when CA send cmd_in, clear after cmd_out return */
	DECLARE_BITMAP(in_bitmap, MAX_SMC_CMD);
	/* set when gtask get cmd_in, clear after cmd_out return */
	DECLARE_BITMAP(doing_bitmap, MAX_SMC_CMD);
	/* set when gtask get cmd_out, clear after cmd_out return */
	DECLARE_BITMAP(out_bitmap, MAX_SMC_CMD);
	smc_buf_lock_t smc_lock;
	volatile uint32_t last_in;
	struct tc_ns_smc_cmd in[MAX_SMC_CMD];
	volatile uint32_t last_out;
	struct tc_ns_smc_cmd out[MAX_SMC_CMD];
};

#define RESLEEP_TIMEOUT 15

bool sigkill_pending(LosTaskCB *tsk);
int smc_context_init(void);
void smc_free_data(void);
int tc_ns_smc(struct tc_ns_smc_cmd *cmd);
int tc_ns_smc_with_no_nr(struct tc_ns_smc_cmd *cmd);
void SetCmdSendState(void);
int init_smc_svc_thread(void);
int smc_wakeup_ca(pid_t ca);
int smc_wakeup_broadcast(void);
int smc_shadow_exit(pid_t ca);
int smc_queue_shadow_worker(uint64_t target);
void fiq_shadow_work_func(uint64_t target);
struct pending_entry *find_pending_entry(pid_t pid);
void foreach_pending_entry(void (*func)(struct pending_entry *));
void put_pending_entry(struct pending_entry *pe);
void show_cmd_bitmap(void);
void wakeup_tc_siq(void);
struct tc_ns_smc_queue *get_cmd_data_buffer(void);

#endif
