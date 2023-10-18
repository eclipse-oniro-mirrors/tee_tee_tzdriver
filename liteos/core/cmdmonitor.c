/*
 * cmd_monitor.c
 *
 * cmdmonitor function, monitor every cmd which is sent to TEE.
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
#include "cmdmonitor.h"
#include "tc_ns_log.h"
#include "smc_smp.h"
#include "mailbox_mempool.h"
#include "tlogger.h"
#include "log_cfg_api.h"
#include "los_adapt.h"

static int g_cmd_need_archivelog;
static LINUX_LIST_HEAD(g_cmd_monitor_list);
static int g_cmd_monitor_list_size;
/* report 2 hours */

#define MAX_CMD_MONITOR_LIST 200
#define MAX_AGENT_CALL_COUNT 250
static mutex_t g_cmd_monitor_lock = PTHREAD_MUTEX_INITIALIZER;

/* independent wq to avoid block system_wq */
static struct workqueue_struct *g_cmd_monitor_wq;
static struct delayed_work g_cmd_monitor_work;
static struct delayed_work g_cmd_monitor_work_archive;
static struct delayed_work g_mem_stat;
static int g_tee_detect_ta_crash;

enum {
	TYPE_CRASH_TA = 1,
	TYPE_CRASH_TEE = 2,
};

#ifndef CONFIG_TEE_LOG_ACHIVE_PATH
#define CONFIG_TEE_LOG_ACHIVE_PATH "/storage/data/log/tee/last_teemsg"
#endif

static void get_time_spec(struct time_spec *time)
{
	time->ts = current_kernel_time();
}

static void schedule_memstat_work(struct delayed_work *work,
	unsigned long delay)
{
	schedule_delayed_work(work, delay);
}
static void schedule_cmd_monitor_work(struct delayed_work *work,
	unsigned long delay)
{
	if (g_cmd_monitor_wq)
		queue_delayed_work(g_cmd_monitor_wq, work, delay);
	else
		schedule_delayed_work(work, delay);
}

void tzdebug_memstat(void)
{
	schedule_memstat_work(&g_mem_stat, msecs_to_jiffies(S_TO_MS));
}

void tzdebug_archivelog(void)
{
	schedule_cmd_monitor_work(&g_cmd_monitor_work_archive,
		msecs_to_jiffies(0));
}

void cmd_monitor_ta_crash(int32_t type)
{
	g_tee_detect_ta_crash = ((type == TYPE_CRASH_TEE) ?
		TYPE_CRASH_TEE : TYPE_CRASH_TA);
	tzdebug_archivelog();
}

bool is_thread_reported(unsigned int tid)
{
	bool ret = false;
	struct cmd_monitor *monitor = NULL;

	if (mutex_lock(&g_cmd_monitor_lock) != 0) {
		tloge("cmd monitor lock fail\n");
		return ret;
	}

	list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
		if (monitor->tid == tid) {
			ret = (monitor->is_reported ||
				monitor->agent_call_count >
				MAX_AGENT_CALL_COUNT);
			break;
		}
	}
	mutex_unlock(&g_cmd_monitor_lock);
	return ret;
}

void memstat_report(void)
{
	int ret;
	struct tee_mem *meminfo = NULL;

	meminfo = mailbox_alloc(sizeof(*meminfo), MB_FLAG_ZERO);
	if (!meminfo) {
		tloge("mailbox alloc failed\n");
		return;
	}

	ret = get_tee_meminfo(meminfo);
	if (!ret)
		tlogd("get meminfo failed\n");
	mailbox_free(meminfo);
}

static void memstat_work(struct work_struct *work)
{
	(void)(work);
	memstat_report();
}

void cmd_monitor_reset_context(void)
{
	struct cmd_monitor *monitor = NULL;
	pid_t pid = OsCurrTaskGet()->processID;
	pid_t tid = OsCurrTaskGet()->taskID;

	if (mutex_lock(&g_cmd_monitor_lock) != 0) {
		tloge("cmdmonitor lock fail\n");
		return;
	}

	list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
		if (monitor->pid == pid && monitor->tid == tid) {
			get_time_spec(&monitor->sendtime);
			if (monitor->agent_call_count + 1 < 0)
				tloge("agent call count add overflow\n");
			else
				monitor->agent_call_count++;
			break;
		}
	}
	mutex_unlock(&g_cmd_monitor_lock);
}

static void show_timeout_cmd_info(struct cmd_monitor *monitor)
{
	long long timedif;
	struct time_spec nowtime;
	get_time_spec(&nowtime);

	/*
	 * 1 year means 1000 * (60*60*24*365) = 0x757B12C00
	 * only 5bytes, so timedif (timedif=nowtime-sendtime) will not overflow
	 */
	timedif = S_TO_MS * (nowtime.ts.tv_sec - monitor->sendtime.ts.tv_sec) +
		(nowtime.ts.tv_nsec - monitor->sendtime.ts.tv_nsec) / S_TO_US;

	/* timeout to 25s, we log the teeos log, and report */
	if ((timedif > CMD_MAX_EXECUTE_TIME * S_TO_MS) && (!monitor->is_reported)) {
		monitor->is_reported = true;
		tloge("[cmd_monitor_tick] pid=%d,pname=%s,tid=%d, "
			"tname=%s, lastcmdid=%u, agent call count:%d, "
			"timedif=%lld ms and report\n",
			monitor->pid, monitor->pname, monitor->tid,
			monitor->tname, monitor->lastcmdid,
			monitor->agent_call_count, timedif);
		tloge("monitor: pid-%d", monitor->pid);
		show_cmd_bitmap();
		g_cmd_need_archivelog = 1;
		wakeup_tc_siq();
		return;
	}

	if (timedif > 1 * S_TO_MS)
		tloge("[cmd_monitor_tick] pid=%d,pname=%s,tid=%d, "
			"lastcmdid=%u,agent call count:%d,timedif=%lld ms\n",
			monitor->pid, monitor->pname, monitor->tid,
			monitor->lastcmdid, monitor->agent_call_count,
			timedif);
}

static void cmd_monitor_tick(void)
{
	struct cmd_monitor *monitor = NULL;
	struct cmd_monitor *tmp = NULL;

	if (mutex_lock(&g_cmd_monitor_lock) != 0) {
		tloge("cmd_monitor lock fail\n");
		return;
	}

	list_for_each_entry_safe(monitor, tmp, &g_cmd_monitor_list, list) {
		if (monitor->returned) {
			g_cmd_monitor_list_size--;
			tloge("[cmd_monitor_tick] pid=%d,pname=%s,tid=%d, "
				"tname=%s,lastcmdid=%u,count=%d,agent call count=%d, "
				"timetotal=%lld us returned, remained command(s)=%d\n",
				monitor->pid, monitor->pname, monitor->tid, monitor->tname,
				monitor->lastcmdid, monitor->count, monitor->agent_call_count,
				monitor->timetotal, g_cmd_monitor_list_size);
			list_del(&monitor->list);
			kfree(monitor);
			continue;
		}
		show_timeout_cmd_info(monitor);
	}

	/* if have cmd in monitor list, we need tick */
	if (g_cmd_monitor_list_size > 0)
		schedule_cmd_monitor_work(&g_cmd_monitor_work, msecs_to_jiffies(S_TO_MS));
	mutex_unlock(&g_cmd_monitor_lock);
}

static void cmd_monitor_tickfn(struct work_struct *work)
{
	(void)(work);
	cmd_monitor_tick();
	/* check tlogcat if have new log */
	tz_log_write();
}

static void cmd_monitor_archivefn(struct work_struct *work)
{
	(void)(work);
	if (tlogger_store_msg(CONFIG_TEE_LOG_ACHIVE_PATH,
		sizeof(CONFIG_TEE_LOG_ACHIVE_PATH)) < 0)
		tloge("[cmd_monitor_tick]tlogger store lastmsg failed\n");

	if (g_tee_detect_ta_crash == TYPE_CRASH_TEE) {
		tloge("detect teeos crash, panic\n");
		report_log_system_panic();
	}

	g_tee_detect_ta_crash = 0;
}

static struct cmd_monitor *init_monitor_locked(void)
{
	struct cmd_monitor *newitem = NULL;

	newitem = kzalloc(sizeof(*newitem), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)newitem)) {
		tloge("[cmd_monitor_tick]kzalloc faild\n");
		return NULL;
	}

	get_time_spec(&newitem->sendtime);
	newitem->count = 1;
	newitem->agent_call_count = 0;
	newitem->returned = false;
	newitem->is_reported = false;
	newitem->pid = OsCurrTaskGet()->processID;
	newitem->tid = OsCurrTaskGet()->taskID;

	LosProcessCB *run_process = OS_PCB_FROM_PID(newitem->pid);
	if (strncpy_s(newitem->pname, TASK_COMM_LEN, run_process->processName, OS_PCB_NAME_LEN) != EOK)
		newitem->pname[0] = '\0';
	if (strncpy_s(newitem->tname, TASK_COMM_LEN, OsCurrTaskGet()->taskName, OS_TCB_NAME_LEN) != EOK)
		newitem->tname[0] = '\0';
	INIT_LIST_HEAD(&newitem->list);
	list_add_tail(&newitem->list, &g_cmd_monitor_list);
	g_cmd_monitor_list_size++;
	return newitem;
}

struct cmd_monitor *cmd_monitor_log(const struct tc_ns_smc_cmd *cmd)
{
	bool found_flag = false;
	pid_t pid;
	pid_t tid;
	struct cmd_monitor *monitor = NULL;

	if (!cmd)
		return NULL;

	pid = OsCurrTaskGet()->processID;
	tid = OsCurrTaskGet()->taskID;
	if (mutex_lock(&g_cmd_monitor_lock) != 0) {
		tloge("cmd monitor lock failed\n");
		return NULL;
	}

	do {
		list_for_each_entry(monitor, &g_cmd_monitor_list, list) {
			if (monitor->pid == pid && monitor->tid == tid) {
				found_flag = true;
				/* restart */
				get_time_spec(&monitor->sendtime);
				monitor->count++;
				monitor->returned = false;
				monitor->is_reported = false;
				monitor->lastcmdid = cmd->cmd_id;
				monitor->agent_call_count = 0;
				break;
			}
		}

		if (!found_flag) {
			if (g_cmd_monitor_list_size >
				MAX_CMD_MONITOR_LIST - 1) {
				tloge("monitor reach max node num\n");
				monitor = NULL;
				break;
			}
			monitor = init_monitor_locked();
			if (!monitor) {
				tloge("init monitor failed\n");
				break;
			}
			monitor->lastcmdid = cmd->cmd_id;
			/* the first cmd will cause timer */
			if (g_cmd_monitor_list_size == 1)
				schedule_cmd_monitor_work(&g_cmd_monitor_work,
					msecs_to_jiffies(S_TO_MS));
		}
	} while (0);
	mutex_unlock(&g_cmd_monitor_lock);

	return monitor;
}

void cmd_monitor_logend(struct cmd_monitor *item)
{
	struct time_spec nowtime;
	long long timedif;

	if (!item)
		return;

	get_time_spec(&nowtime);
	/*
	 * get time value D (timedif=nowtime-sendtime),
	 * we do not care about overflow
	 * 1 year means 1000000 * (60*60*24*365) = 0x1CAE8C13E000
	 * only 6bytes, will not overflow
	 */
	tloge("time : item s %lld ns %lld nowtime s %lld ns %lld total %lld\n",
		(long long)item->sendtime.ts.tv_sec, (long long)item->sendtime.ts.tv_nsec,
		(long long)nowtime.ts.tv_sec, (long long)nowtime.ts.tv_nsec, (long long)item->timetotal);
	timedif = S_TO_US * (nowtime.ts.tv_sec - item->sendtime.ts.tv_sec) +
		(nowtime.ts.tv_nsec - item->sendtime.ts.tv_nsec) / S_TO_MS;
	item->timetotal += timedif;
	item->returned = true;
}

void do_cmd_need_archivelog(void)
{
	if (g_cmd_need_archivelog == 1) {
		g_cmd_need_archivelog = 0;
		schedule_cmd_monitor_work(&g_cmd_monitor_work_archive,
			msecs_to_jiffies(S_TO_MS));
	}
}

void init_cmd_monitor(void)
{
	g_cmd_monitor_wq = alloc_ordered_workqueue("tz_cmd_monitor_wq", 0);
	if (!g_cmd_monitor_wq)
		tloge("alloc cmd monitor wq failed\n");
	init_deferrable_work((struct delayed_work *)
		(uintptr_t)&g_cmd_monitor_work, cmd_monitor_tickfn);
	init_deferrable_work((struct delayed_work *)
		(uintptr_t)&g_cmd_monitor_work_archive, cmd_monitor_archivefn);
	init_deferrable_work((struct delayed_work *)
		(uintptr_t)&g_mem_stat, memstat_work);

}
