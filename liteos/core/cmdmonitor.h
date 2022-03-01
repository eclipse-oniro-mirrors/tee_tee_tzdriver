/*
 * cmd_monitor.h
 *
 * cmdmonitor function declaration
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
#ifndef CMD_MONITOR_H
#define CMD_MONITOR_H

#include "tzdebug.h"
#include "teek_ns_client.h"

#define TASK_COMM_LEN OS_TCB_NAME_LEN

/*
 * when cmd execute more than 25s in tee,
 * it will be terminated when CA is killed
 */
#define CMD_MAX_EXECUTE_TIME 25U
#define S_TO_MS 1000
#define S_TO_US 1000000

struct time_spec {
	struct timespec ts;
};

struct cmd_monitor {
	struct list_head list;
	struct time_spec sendtime;
	int count;
	bool returned;
	bool is_reported;
	pid_t pid;
	pid_t tid;
	char pname[TASK_COMM_LEN];
	char tname[TASK_COMM_LEN];
	unsigned int lastcmdid;
	long long timetotal;
	int agent_call_count;
};

struct cmd_monitor *cmd_monitor_log(const struct tc_ns_smc_cmd *cmd);
void cmd_monitor_reset_context(void);
void cmd_monitor_logend(struct cmd_monitor *item);
void init_cmd_monitor(void);
void do_cmd_need_archivelog(void);
bool is_thread_reported(unsigned int tid);
void tzdebug_archivelog(void);
void cmd_monitor_ta_crash(int32_t type);
void memstat_report(void);
void tzdebug_memstat(void);

#endif
