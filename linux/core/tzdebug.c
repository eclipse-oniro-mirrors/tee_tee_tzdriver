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
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <stdarg.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <securec.h>
#include <asm/io.h>
#include "tc_ns_log.h"
#include "tc_ns_client.h"
#include "tc_client_driver.h"
#include "teek_ns_client.h"
#include "smc_smp.h"
#include "teek_client_constants.h"
#include "mailbox_mempool.h"
#include "tlogger.h"
#include "cmdmonitor.h"
#include "session_manager.h"

#define DEBUG_OPT_LEN 128

#ifdef CONFIG_TA_MEM_INUSE_ONLY
#define TA_MEMSTAT_ALL 0
#else
#define TA_MEMSTAT_ALL 1
#endif

static struct dentry *g_tz_dbg_dentry;

typedef void (*tzdebug_opt_func)(const char *param);

struct opt_ops {
	char *name;
	tzdebug_opt_func func;
};

static DEFINE_MUTEX(g_meminfo_lock);
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
	mb_pack->operation.params[0].memref.buffer = virt_to_phys(statmem);
	mb_pack->operation.params[0].memref.size = sizeof(*statmem);
	mb_pack->operation.buffer_h_addr[0] =
		(uint64_t)virt_to_phys(statmem) >> ADDR_TRANS_NUM;
	mb_pack->operation.params[1].value.a = flag;
	mb_pack->operation.params[1].value.b = history;
	smc_cmd.operation_phys =
		(unsigned int)virt_to_phys(&mb_pack->operation);
	smc_cmd.operation_h_phys =
		(uint64_t)virt_to_phys(&mb_pack->operation) >> ADDR_TRANS_NUM;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("send dump mem failed\n");
	}
	tz_log_write();
	mailbox_free(mb_pack);
	return ret;
}

void tee_dump_mem(void)
{
	tzmemdump(NULL);
	if (tlogger_store_msg(CONFIG_TEE_LOG_ACHIVE_PATH,
		sizeof(CONFIG_TEE_LOG_ACHIVE_PATH)) < 0)
		tloge("[cmd_monitor_tick]tlogger store lastmsg failed\n");
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
EXPORT_SYMBOL(get_tee_meminfo);

static void archivelog(const char *param)
{
	(void)param;
	tzdebug_archivelog();
}

static void tzdump(const char *param)
{
	(void)param;
	show_cmd_bitmap();
	wakeup_tc_siq(SIQ_DUMP_SHELL);
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

static void tz_srv_sess_dump(const char *param)
{
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };

	(void)param;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_DUMP_SRV_SESS;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	if (tc_ns_smc(&smc_cmd))
		tloge("send dump service session failed\n");
}

static void tzmemstat(const char *param)
{
	(void)param;
	tzdebug_memstat();
}

static void tzlogwrite(const char *param)
{
	(void)param;
	(void)tz_log_write();
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
#define MAX_VALUE_LEN 8U
#define MAX_ADDRSTR_LEN 18U
struct addr_ops {
	uint32_t pos[MAX_CMD_NUM];
	char address[MAX_CMD_LINE];
	char value[MAX_CMD_LINE];
};

static struct addr_ops g_sec_addr;

static int parse_param(const char *param, uint32_t len)
{
	uint32_t i;
	uint32_t j;

	/*
	 * param format as follows:
	 * (r)/(w):addr(Decimal):value
	 * 'w' for writing a value to a given addr
	 * 'r' for reading a value form a giver addr
	 */
	j = 0;
	for (i = 0; i < len; i++) {
		if (param[i] == ':') {
			if (j < MAX_CMD_NUM - 1)
				g_sec_addr.pos[j] = i;
			j++;
		}
	}
	if (j >= MAX_CMD_NUM ) {  /* Max number of ':' is 2 */
		tloge("cmd invalid\n");
		return -EINVAL;
	}

	if ((g_sec_addr.pos[1] - g_sec_addr.pos[0] - 1 >= MAX_ADDRSTR_LEN ) || (len - g_sec_addr.pos[1]  >= MAX_VALUE_LEN)) {
		tloge("invalid param\n");
		return -EINVAL;
	}
	if (param[0] != 'r' && param[0] != 'w' ) {
		tloge("cmd not support\n");
		return -EINVAL;
	}

	i = 0;
	for (j = g_sec_addr.pos[0] + 1; j <= g_sec_addr.pos[1] - 1; j++) /* skip ':'*/
		g_sec_addr.address[i++] = param[j];
	g_sec_addr.address[i] = '\0';

	i = 0;
	for (j = g_sec_addr.pos[1] + 1; j <= len; j++)
		g_sec_addr.value[i++] = param[j];
	g_sec_addr.value[i] = '\0';
	return 0;
}
void tz_secmem_test(const char *param)
{
	void __iomem *remap_addr = NULL;
	void *addr = NULL;
	uint32_t val;
	unsigned long long tmp;
	uint32_t len;

	/* if strlen is negative, len must be larger than MAX_PARAM_LINE, so it's invalied */
	len = (uint32_t)strlen(param);
	if (len >= MAX_PARAM_LINE) {
		tloge("param invalid\n");
		return;
	}

	if (parse_param(param, len) != 0) {
		tloge("parse params fail\n");
		return;
	}
	tloge("the second string : %s\n", g_sec_addr.address);

	if (kstrtoull(g_sec_addr.address + 2, 16, &tmp) < 0) { /* add 2 for skip '0x' */
		tloge("str address to unsigned long fail\n");
		return;
	}
	addr = (void *)(uintptr_t)tmp;

	if (kstrtoull(g_sec_addr.value, 10, &tmp) < 0) {
		tloge("str val to unsigned long fail\n");
		return;
	}
	val = (uint32_t)tmp;
	tloge("val = %u\n", val);

	remap_addr = ioremap((phys_addr_t)(uintptr_t)addr, MAX_MEM_SIZE);
	if (!remap_addr) {
		tloge("remap_addr failed\n");
		return;
	}
	tloge("remap_addr succ\n");
	if (param[0] == 'w') {
		tloge("read before write : %u \n", *((uint32_t *)remap_addr));
		tloge("write val : %u \n", val);
		*((uint32_t *)remap_addr) = val;
	} else {
		tloge("read addr value : %u \n", *((uint32_t *)remap_addr));
	}
	iounmap(remap_addr);
}

static struct opt_ops g_opt_arr[] = {
	{"archivelog", archivelog},
	{"dump", tzdump},
	{"memdump", tzmemdump},
	{"logwrite", tzlogwrite},
	{"dump_service", dump_services_status},
	{"memstat", tzmemstat},
	{"secmem_test", tz_secmem_test},
	{"srv_sess_dump", tz_srv_sess_dump},
};

static ssize_t tz_dbg_opt_read(struct file *filp, char __user *ubuf,
	size_t cnt, loff_t *ppos)
{
	char *obuf = NULL;
	char *p = NULL;
	ssize_t ret;
	uint32_t oboff = 0;
	uint32_t i;

	(void)(filp);

	obuf = kzalloc(DEBUG_OPT_LEN, GFP_KERNEL);
	if (!obuf)
		return -ENOMEM;
	p = obuf;

	for (i = 0; i < ARRAY_SIZE(g_opt_arr); i++) {
		int len = snprintf_s(p, DEBUG_OPT_LEN - oboff, DEBUG_OPT_LEN - oboff - 1,
			"%s ", g_opt_arr[i].name);
		if (len < 0) {
			kfree(obuf);
			tloge("snprintf opt name of idx %d failed\n", i);
			return -EINVAL;
		}
		p += len;
		oboff += len;
	}
	obuf[oboff - 1] = '\n';

	ret = simple_read_from_buffer(ubuf, cnt, ppos, obuf, oboff);
	kfree(obuf);

	return ret;
}

static ssize_t tz_dbg_opt_write(struct file *filp,
	const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char buf[128] = {0};
	char *value = NULL;
	char *p = NULL;
	uint32_t i = 0;

	if (!ubuf || !filp || !ppos)
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
	.owner   = THIS_MODULE,
	.open    = tz_memstat_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};
#endif

static const struct file_operations g_tz_dbg_opt_fops = {
	.owner = THIS_MODULE,
	.read = tz_dbg_opt_read,
	.write = tz_dbg_opt_write,
};

int tzdebug_init(void)
{
#if defined(DEF_ENG) || defined(CONFIG_TZDRIVER_MODULE)
	g_tz_dbg_dentry = debugfs_create_dir("tzdebug", NULL);
	if (!g_tz_dbg_dentry)
		return -1;

	debugfs_create_file("opt", 0660, g_tz_dbg_dentry, NULL,
		&g_tz_dbg_opt_fops);

#ifdef CONFIG_MEMSTAT_DEBUGFS
	debugfs_create_file("memstat", 0444, g_tz_dbg_dentry, NULL,
		&g_tz_dbg_memstat_fops);
#endif

#else
	(void)g_tz_dbg_dentry;
	(void)g_tz_dbg_opt_fops;
#endif
	return 0;
}

void tzdebug_exit(void)
{
#if defined(DEF_ENG) || defined(CONFIG_TZDRIVER_MODULE)
	if (!g_tz_dbg_dentry)
		return;

	debugfs_remove_recursive(g_tz_dbg_dentry);
	g_tz_dbg_dentry = NULL;
#endif
}
