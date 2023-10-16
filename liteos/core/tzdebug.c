/*
 * tzdebug.c
 *
 * for tzdriver debug
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
#include "tzdebug.h"
#include "tc_ns_log.h"
#include "tc_ns_client.h"
#include "tc_client_driver.h"
#include "teek_ns_client.h"
#include "smc_smp.h"
#include "teek_client_constants.h"
#include "mailbox_mempool.h"
#include "tlogger.h"
#include "session_manager.h"
#include "cmdmonitor.h"
#include "shcmd.h"

#define DEBUG_OPT_LEN 128

#ifdef CONFIG_TA_MEM_INUSE_ONLY
#define TA_MEMSTAT_ALL 0
#else
#define TA_MEMSTAT_ALL 1
#endif

typedef void (*tzdebug_opt_func)(const char *param);

struct opt_ops {
	char *name;
	tzdebug_opt_func func;
};

static mutex_t g_meminfo_lock = PTHREAD_MUTEX_INITIALIZER;
static struct tee_mem g_tee_meminfo;
static void tzmemdump(const char *param);
static int send_dump_mem(int flag, int history, const struct tee_mem *statmem)
{
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	struct mb_cmd_pack *mb_pack = NULL;
	int ret = 0;

	if (!statmem) {
		tloge("statmem is NULL\n");
		return -EINVAL;
	}
	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack)
		return -ENOMEM;

	smc_cmd.cmd_id = GLOBAL_CMD_ID_DUMP_MEMINFO;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	mb_pack->operation.paramtypes = teec_param_types(
		TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	mb_pack->operation.params[0].memref.buffer = virt_to_phys((void *)statmem);
	mb_pack->operation.params[0].memref.size = sizeof(*statmem);
	mb_pack->operation.buffer_h_addr[0] = 0;
	mb_pack->operation.params[1].value.a = flag;
	mb_pack->operation.params[1].value.b = history;
	smc_cmd.operation_phys =
		(unsigned int)virt_to_phys((void *)&mb_pack->operation);
	smc_cmd.operation_h_phys = 0;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("send dump mem failed\n");
	}
	mailbox_free(mb_pack);
	return ret;
}

/* get meminfo (tee_mem + N * ta_mem < 4Kbyte) from tee */
static int get_tee_meminfo_cmd(void)
{
	int ret;
	struct tee_mem *mem = NULL;

	mem = mailbox_alloc(sizeof(*mem), MB_FLAG_ZERO);
	if (!mem)
		return -ENOMEM;

	ret = send_dump_mem(0, TA_MEMSTAT_ALL, mem);
	if (ret) {
		tloge("send dump failed\n");
		mailbox_free(mem);
		return ret;
	}

	mutex_lock(&g_meminfo_lock);
	ret = memcpy_s(&g_tee_meminfo, sizeof(g_tee_meminfo), mem, sizeof(*mem));
	if (ret)
		tloge("memcpy failed\n");
	mutex_unlock(&g_meminfo_lock);
	mailbox_free(mem);

	return ret;
}

static atomic_t g_cmd_send = ATOMIC_INIT(1);

void set_cmd_send_state(void)
{
	atomic_set(&g_cmd_send, 1);
}

int get_tee_meminfo(struct tee_mem *meminfo)
{
	errno_t s_ret;

	if (!meminfo)
		return -EINVAL;

	if (atomic_read(&g_cmd_send)) {
		if (get_tee_meminfo_cmd())
			return -EFAULT;
	} else {
		atomic_set(&g_cmd_send, 0);
	}

	mutex_lock(&g_meminfo_lock);
	s_ret = memcpy_s(meminfo, sizeof(*meminfo),
		&g_tee_meminfo, sizeof(g_tee_meminfo));
	mutex_unlock(&g_meminfo_lock);
	if (s_ret)
		return -1;

	return 0;
}

static void archivelog(const char *param)
{
	(void)param;
	tzdebug_archivelog();
}

static void tzdump(const char *param)
{
	(void)param;
	show_cmd_bitmap();
	wakeup_tc_siq();
}

static void tzmemdump(const char *param)
{
	struct tee_mem *mem = NULL;

	(void)param;
	mem = mailbox_alloc(sizeof(*mem), MB_FLAG_ZERO);
	if (!mem) {
		tloge("mailbox alloc failed\n");
		return;
	}

	if (send_dump_mem(1, 1, mem))
		tloge("send dump mem failed\n");
	mailbox_free(mem);
}

static void tzmemstat(const char *param)
{
	(void)param;
	tzdebug_memstat();
}

static void tzlogwrite(const char *param)
{
	(void)param;
}

#define OFFSET_VALUE_BIT 8U
static void get_value(const char *param, uint32_t *value, uint32_t *index)
{
	uint32_t i;
	uint32_t val = 0;

	for (i = 0; i < OFFSET_VALUE_BIT; i++) {
		if (param[i] > '9' || param[i] < '0') {
			*value = val;
			*index = i;
			return;
		}
		val = (val * 10) + param[i] - '0';
	}

	*value = val;
	*index = i;
	return;
}

#define MAX_CMD_NUM  3
#define MAX_CMD_LINE 20
#define MAX_PARAM_LINE 60
#define MAX_MEM_SIZE 0x4000U
#define MAX_VALUE_LEN 8
#define MAX_ADDRSTR_LEN 18

static struct opt_ops g_opt_arr[] = {
	{"archivelog", archivelog},
	{"dump", tzdump},
	{"memdump", tzmemdump},
	{"logwrite", tzlogwrite},
	{"dump_service", dump_services_status},
	{"memstat", tzmemstat},
};

static ssize_t tz_dbg_opt_write(struct file *filp,
	const char __user *ubuf, size_t cnt)
{
	char buf[128] = {0};
	char *value = NULL;
	char *p = NULL;
	uint32_t i = 0;

	if (!ubuf || !filp)
		return -EINVAL;

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (!cnt)
		return -EINVAL;

	if (copy_from_user(buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;
	if (cnt > 0 && buf[cnt - 1] == '\n')
		buf[cnt - 1] = 0;
	value = buf;
	p = strsep(&value, ":"); /* when buf has no :, value may be NULL */
	if (!p)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(g_opt_arr); i++) {
		if (!strncmp(p, g_opt_arr[i].name,
			strlen(g_opt_arr[i].name)) &&
			strlen(p) == strlen(g_opt_arr[i].name)) {
			g_opt_arr[i].func(value);
			return cnt;
		}
	}
	return -EFAULT;
}

#ifdef CONFIG_MEMSTAT_DEBUGFS
static int memstat_debug_show(struct seq_file *m, void *v)
{
	struct tee_mem *mem_stat = NULL;
	int ret;
	uint32_t i;

	mem_stat = kzalloc(sizeof(*mem_stat), GFP_KERNEL);
	if (!mem_stat)
		return -ENOMEM;

	ret = get_tee_meminfo(mem_stat);
	if (ret != 0) {
		tloge("get tee meminfo failed\n");
		kfree(mem_stat);
		mem_stat = NULL;
		return -EINVAL;
	}

	seq_printf(m, "TotalMem:%u Pmem:%u Free_Mem:%u Free_Mem_Min:%u TA_Num:%u\n",
		mem_stat->total_mem, mem_stat->pmem, mem_stat->free_mem, mem_stat->free_mem_min, mem_stat->ta_num);

	for (i = 0; i < mem_stat->ta_num; i++)
		seq_printf(m, "ta_name:%s ta_pmem:%u pmem_max:%u pmem_limit:%u\n",
			mem_stat->ta_mem_info[i].ta_name, mem_stat->ta_mem_info[i].pmem,
			mem_stat->ta_mem_info[i].pmem_max, mem_stat->ta_mem_info[i].pmem_limit);

	kfree(mem_stat);
	mem_stat = NULL;
	return 0;
}

static int tz_memstat_open(struct inode *inode, struct file *file)
{
	return single_open(file, memstat_debug_show, NULL);
}

static const struct file_operations g_tz_dbg_memstat_fops = {
	.open    = tz_memstat_open,
};
#endif

static const struct file_operations_vfs g_tz_dbg_opt_fops = {
	.write = tz_dbg_opt_write,
};

#define TC_NS_CLIENT_TZDEBUG "/dev/tzdebug"
int tzdebug_init(void)
{
	int ret = create_tc_client_device(TC_NS_CLIENT_TZDEBUG, &g_tz_dbg_opt_fops);
	if (ret != EOK)
		return ret;

	return 0;
}

void tzdebug_exit(void)
{

}

int tee_shell_cmd_mem(int argc, const char **argv)
{
	char buf[128] = {0};
	tloge("Begin to show tee mem\n");
	tzmemdump(buf);
	return LOS_OK;
}

int tee_shell_cmd_dump(int argc, const char **argv)
{
	char buf[128] = {0};
	tloge("Begin to show dump mem\n");
	tzdump(buf);
	return LOS_OK;
}

SHELLCMD_ENTRY(teememdump_shellcmd, CMD_TYPE_STD, "teememdump", XARGS, (CmdCallBackFunc)tee_shell_cmd_mem);
SHELLCMD_ENTRY(teedump_shellcmd, CMD_TYPE_STD, "teedump", XARGS, (CmdCallBackFunc)tee_shell_cmd_dump);
