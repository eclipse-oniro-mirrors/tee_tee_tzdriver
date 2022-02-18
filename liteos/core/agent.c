/*
 * agent.c
 *
 * agent manager function, such as register and send cmd
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
#include "agent.h"
#include <securec.h>
#include "teek_client_constants.h"
#include "teek_ns_client.h"
#include "smc_smp.h"
#include "mem.h"
#include "tc_ns_log.h"
#include "mailbox_mempool.h"
#include "tc_client_driver.h"
#include "los_adapt.h"
#include "cmdmonitor.h"

#ifdef CONFIG_CMS_CAHASH_AUTH
#define HASH_FILE_MAX_SIZE         CONFIG_HASH_FILE_SIZE
#else
#define HASH_FILE_MAX_SIZE         (16 * 1024)
#endif
#define AGENT_BUFF_SIZE            (4 * 1024)
#define AGENT_MAX                  32
#define PAGE_ORDER_RATIO           2

static struct list_head g_tee_agent_list;

struct agent_control {
	spinlock_t lock;
	struct list_head agent_list;
};

static struct agent_control g_agent_control;

int __attribute__((weak)) is_allowed_agent_ca(const struct ca_info *ca,
	bool check_agent_id)
{
	(void)ca;
	(void)check_agent_id;

	return -EFAULT;
}

static int get_ca_path_and_uid(LosTaskCB *ca_task, struct ca_info *ca)
{
	char *path = NULL;
	int message_size;
	char *tpath = NULL;

	tpath = kmalloc(MAX_PATH_SIZE, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)tpath)) {
		tloge("tpath kmalloc fail\n");
		return -ENOMEM;
	}

	path = get_process_path(ca_task, tpath, MAX_PATH_SIZE);
	if (IS_ERR_OR_NULL(path)) {
		tloge("get process path failed\n");
		kfree(tpath);
		return -ENOMEM;
	}

	message_size = snprintf_s(ca->path, MAX_PATH_SIZE,
		MAX_PATH_SIZE - 1, "%s", path);
	if (message_size <= 0) {
		tloge("pack path failed\n");
		kfree(tpath);
		return -EFAULT;
	}

	ca->uid = get_task_uid(ca_task);
	if (ca->uid < 0) {
		kfree(tpath);
		return -EPERM;
	}
	tlogd("ca_task->comm is %s, path is %s, ca uid is %u\n", OsCurrTaskGet()->taskName, path, ca->uid);

	kfree(tpath);
	return 0;
}

int check_ext_agent_access(LosTaskCB *ca_task, uint32_t agent_id)
{
	int ret;
	struct ca_info agent_ca = { {0}, 0, 0 };

	ret = get_ca_path_and_uid(ca_task, &agent_ca);
	if (ret) {
		tloge("get cp path or uid failed\n");
		return ret;
	}
	agent_ca.agent_id = agent_id;

	return is_allowed_agent_ca(&agent_ca, true);
}

static int get_buf_len(const uint8_t *inbuf, uint32_t *buf_len)
{
	if (copy_from_user(buf_len, inbuf, sizeof(*buf_len))) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	if (*buf_len > HASH_FILE_MAX_SIZE) {
		tloge("ERROR: file size[0x%x] too big\n", *buf_len);
		return -EFAULT;
	}

	return 0;
}

static int send_set_smc_cmd(struct mb_cmd_pack *mb_pack,
	struct tc_ns_smc_cmd *smc_cmd, unsigned int cmd_id,
	const uint8_t *buf_to_tee, uint32_t buf_len)
{
	int ret = 0;

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INPUT << TEE_PARAM_NUM);
	mb_pack->operation.params[0].value.a =
		(unsigned int)virt_to_phys((char *)buf_to_tee);
	mb_pack->operation.params[0].value.b = 0;
	mb_pack->operation.params[1].value.a = buf_len;
	smc_cmd->cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd->cmd_id = cmd_id;
	smc_cmd->operation_phys = virt_to_phys(&mb_pack->operation);
	smc_cmd->operation_h_phys = 0;
	if (tc_ns_smc(smc_cmd)) {
		ret = -EPERM;
		tloge("set native hash failed\n");
	}

	return ret;
}

int tc_ns_set_native_hash(unsigned long arg, unsigned int cmd_id)
{
	int ret;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	uint8_t *inbuf = (uint8_t *)(uintptr_t)arg;
	uint32_t buf_len = 0;
	uint8_t *buf_to_tee = NULL;
	struct mb_cmd_pack *mb_pack = NULL;

	if (!inbuf)
		return -EINVAL;

	if (tc_ns_get_uid() != TEECD_UID) {
		tloge("It is a fake tee agent\n");
		return -EACCES;
	}

	if (get_buf_len(inbuf, &buf_len))
		return -EFAULT;

	buf_to_tee = mailbox_alloc(buf_len, 0);
	if (!buf_to_tee) {
		tloge("failed to alloc memory!\n");
		return -ENOMEM;
	}

	if (copy_from_user(buf_to_tee, inbuf, buf_len)) {
		tloge("copy from user failed\n");
		mailbox_free(buf_to_tee);
		return -EFAULT;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc cmd pack failed\n");
		mailbox_free(buf_to_tee);
		return -ENOMEM;
	}

	ret = send_set_smc_cmd(mb_pack, &smc_cmd, cmd_id, buf_to_tee, buf_len);
	mailbox_free(buf_to_tee);
	mailbox_free(mb_pack);

	return ret;
}

int tc_ns_late_init(unsigned long arg)
{
	int ret = 0;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	uint32_t index = (uint32_t)arg; /* index is uint32_t, no truncate risk */
	struct mb_cmd_pack *mb_pack = NULL;

	if (tc_ns_get_uid() != TEECD_UID) {
		tloge("It is a fake tee agent\n");
		return -EACCES;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc cmd pack failed\n");
		return -ENOMEM;
	}

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT;
	mb_pack->operation.params[0].value.a = index;

	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_LATE_INIT;
	smc_cmd.operation_phys = virt_to_phys(&mb_pack->operation);
	smc_cmd.operation_h_phys = 0;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("late int failed\n");
	}
	mailbox_free(mb_pack);

	return ret;
}

void send_event_response_single(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	unsigned long flags;
	unsigned int agent_id = 0;

	if (!dev_file)
		return;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file) {
			agent_id = event_data->agent_id;
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
	send_event_response(agent_id);
	return;
}

struct smc_event_data *find_event_control(unsigned int agent_id)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp_data = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry(event_data, &g_agent_control.agent_list, head) {
		if (event_data->agent_id == agent_id) {
			tmp_data = event_data;
			get_agent_event(event_data);
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	return tmp_data;
}

static void unmap_agent_buffer(struct smc_event_data *event_data)
{
	if (!event_data) {
		tloge("event data is NULL\n");
		return;
	}

	if (IS_ERR_OR_NULL(event_data->agent_buff_user))
		return;

	if (LOS_UnMMap((unsigned long)(uintptr_t)event_data->agent_buff_user,
		event_data->agent_buff_size))
		tloge("unmap failed\n");

	event_data->agent_buff_user = NULL;
}

static void free_event_control(unsigned int agent_id)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp_event = NULL;
	unsigned long flags;
	bool find = false;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp_event,
		&g_agent_control.agent_list, head) {
		if (event_data->agent_id == agent_id) {
			list_del(&event_data->head);
			find = true;
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	if (!find)
		return;

	unmap_agent_buffer(event_data);
	mailbox_free(event_data->agent_buff_kernel);
	event_data->agent_buff_kernel = NULL;
	put_agent_event(event_data);
}

static int init_agent_context(unsigned int agent_id,
	const struct tc_ns_smc_cmd *smc_cmd,
	struct smc_event_data **event_data)
{
	*event_data = find_event_control(agent_id);
	if (!(*event_data)) {
		tloge("agent %u not exist\n", agent_id);
		return -EINVAL;
	}
	tlogd("agent-0x%x: returning client command", agent_id);

	ISB;
	DSB;

	return 0;
}

static int wait_agent_response(struct smc_event_data *event_data)
{
	int ret = 0;
	bool answered = true;
	int rc;

	do {
		answered = true;
		rc = wait_event_interruptible_timeout(event_data->ca_pending_wq,
			atomic_read(&event_data->ca_run),
			(long)(RESLEEP_TIMEOUT * HZ));
		if (rc)
			continue;
		tloge("agent wait event is timeout\n");
		/* if no kill signal, just resleep before agent wake */
		if (!sigkill_pending(OsCurrTaskGet())) {
			answered = false;
		} else {
			tloge("CA is killed, no need to wait agent response\n");
			event_data->ret_flag = 0;
			ret = -EFAULT;
		}
	} while (!answered);

	return ret;
}

int agent_process_work(const struct tc_ns_smc_cmd *smc_cmd,
	unsigned int agent_id)
{
	struct smc_event_data *event_data = NULL;
	int ret;

	if (!smc_cmd) {
		tloge("smc_cmd is null\n");
		return -EINVAL;
	}

	if (init_agent_context(agent_id, smc_cmd, &event_data))
		return -EINVAL;

	if (atomic_read(&event_data->agent_ready) == AGENT_CRASHED) {
		tloge("agent 0x%x is killed and restarting\n", agent_id);
		put_agent_event(event_data);
		return -EFAULT;
	}
	event_data->ret_flag = 1;
	/* Wake up the agent that will process the command */
	tlogd("agent process work: wakeup the agent");
	wake_up(&event_data->wait_event_wq);
	tlogd("agent 0x%x request, goto sleep, pe->run=%d\n",
		  agent_id, atomic_read(&event_data->ca_run));

	ret = wait_agent_response(event_data);
	atomic_set(&event_data->ca_run, 0);
	put_agent_event(event_data);
	/*
	 * when agent work is done, reset cmd monitor time
	 * add agent call count, cause it's a new smc cmd.
	 */
	cmd_monitor_reset_context();
	return ret;
}

int is_agent_alive(unsigned int agent_id)
{
	struct smc_event_data *event_data = NULL;

	event_data = find_event_control(agent_id);
	if (event_data) {
		put_agent_event(event_data);
		return AGENT_ALIVE;
	}

	return AGENT_DEAD;
}

int tc_ns_wait_event(unsigned int agent_id)
{
	int ret = -EINVAL;
	struct smc_event_data *event_data = NULL;

	if ((tc_ns_get_uid() != TEECD_UID) && check_ext_agent_access(OsCurrTaskGet(), agent_id)) {
		tloge("It is a fake tee agent\n");
		return -EPERM;
	}
	tlogd("agent %u waits for command\n", agent_id);

	event_data = find_event_control(agent_id);
	if (event_data) {
		/* only when agent wait event, it's in ready state to work */
		atomic_set(&(event_data->agent_ready), AGENT_READY);
		ret = wait_event_interruptible(event_data->wait_event_wq,
			event_data->ret_flag);
		put_agent_event(event_data);
	}

	return ret;
}

int tc_ns_sync_sys_time(const struct tc_ns_client_time *tc_ns_time)
{
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	int ret = 0;
	struct tc_ns_client_time tmp_tc_ns_time = {0};
	struct mb_cmd_pack *mb_pack = NULL;

	if (!tc_ns_time) {
		tloge("tc_ns_time is NULL input buffer\n");
		return -EINVAL;
	}

	if (tc_ns_get_uid() != TEECD_UID) {
		tloge("It is a fake tee agent\n");
		return -EINVAL;
	}

	if (copy_from_user(&tmp_tc_ns_time, tc_ns_time,
		sizeof(tmp_tc_ns_time))) {
		tloge("copy from user failed\n");
		return -EFAULT;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mb pack failed\n");
		return -ENOMEM;
	}

	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_ADJUST_TIME;
	smc_cmd.err_origin = tmp_tc_ns_time.seconds;
	smc_cmd.ret_val = (int)tmp_tc_ns_time.millis;

	if (tc_ns_smc(&smc_cmd)) {
		tloge("tee adjust time failed, return error\n");
		ret = -EPERM;
	}
	mailbox_free(mb_pack);

	return ret;
}

static struct smc_event_data *check_response_access(unsigned int agent_id)
{
	struct smc_event_data *event_data = find_event_control(agent_id);

	if (!event_data) {
		tloge("Can't get event_data\n");
		return NULL;
	}

	if ((tc_ns_get_uid() != TEECD_UID) &&
		check_ext_agent_access(OsCurrTaskGet(), agent_id)) {
		tloge("It is a fake tee agent\n");
		put_agent_event(event_data);
		return NULL;
	}

	return event_data;
}

static void process_send_event_response(struct smc_event_data *event_data)
{
	if (!event_data->ret_flag)
		return;

	event_data->ret_flag = 0;
	/* Send the command back to the TA session waiting for it */
	tlogd("agent wakeup ca\n");
	atomic_set(&event_data->ca_run, 1);
	/* make sure reset working_ca before wakeup CA */
	wake_up(&event_data->ca_pending_wq);
}

int tc_ns_send_event_response(unsigned int agent_id)
{
	struct smc_event_data *event_data = NULL;

	event_data = check_response_access(agent_id);
	if (!event_data) {
		tlogd("agent %u pre-check failed\n", agent_id);
		return -EINVAL;
	}

	tlogd("agent %u sends answer back\n", agent_id);
	process_send_event_response(event_data);
	put_agent_event(event_data);

	return 0;
}

void send_event_response(unsigned int agent_id)
{
	struct smc_event_data *event_data = find_event_control(agent_id);

	if (!event_data) {
		tloge("Can't get event_data\n");
		return;
	}

	tloge("agent 0x%x sends answer back\n", agent_id);
	atomic_set(&event_data->agent_ready, AGENT_CRASHED);
	process_send_event_response(event_data);
	put_agent_event(event_data);
}

static void init_restart_agent_node(struct tc_ns_dev_file *dev_file,
	struct smc_event_data *event_data)
{
	tloge("agent: 0x%x restarting\n", event_data->agent_id);
	event_data->ret_flag = 0;
	event_data->owner = dev_file;
	event_data->pid = OsCurrTaskGet()->processID;
	atomic_set(&event_data->agent_ready, AGENT_REGISTERED);
	init_waitqueue_head(&(event_data->wait_event_wq));
	init_waitqueue_head(&(event_data->send_response_wq));
	init_waitqueue_head(&(event_data->ca_pending_wq));
	atomic_set(&(event_data->ca_run), 0);
}

static int create_new_agent_node(struct tc_ns_dev_file *dev_file,
	struct smc_event_data **event_data, unsigned int agent_id,
	uintptr_t *agent_buff, uint32_t agent_buff_size)
{
	*agent_buff = (uintptr_t)mailbox_alloc(agent_buff_size, MB_FLAG_ZERO);
	if (!(*agent_buff)) {
		tloge("alloc agent buff failed\n");
		return -ENOMEM;
	}
	*event_data = kzalloc(sizeof(**event_data), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)(*event_data))) {
		mailbox_free((void *)*agent_buff);
		*agent_buff = (uintptr_t)NULL;
		*event_data = NULL;
		tloge("alloc event data failed\n");
		return -ENOMEM;
	}
	(*event_data)->agent_id = agent_id;
	(*event_data)->ret_flag = 0;
	(*event_data)->agent_buff_kernel = (void *)*agent_buff;
	(*event_data)->agent_buff_size = agent_buff_size;
	(*event_data)->owner = dev_file;
	(*event_data)->pid = OsCurrTaskGet()->processID;
	atomic_set(&(*event_data)->agent_ready, AGENT_REGISTERED);
	init_waitqueue_head(&(*event_data)->wait_event_wq);
	init_waitqueue_head(&(*event_data)->send_response_wq);
	INIT_LIST_HEAD(&(*event_data)->head);
	init_waitqueue_head(&(*event_data)->ca_pending_wq);
	atomic_set(&(*event_data)->ca_run, 0);

	return 0;
}

static bool is_built_in_agent(unsigned int agent_id)
{
	if (agent_id == AGENT_FS_ID ||
		agent_id == AGENT_MISC_ID ||
		agent_id == AGENT_SOCKET_ID ||
		agent_id == SECFILE_LOAD_AGENT_ID)
		return true;

	return false;
}

static unsigned long agent_buffer_map(unsigned long buffer, uint32_t size)
{
	vaddr_t user_addr;
	int ret;

	if (!IS_PAGE_ALIGNED(buffer) || !IS_PAGE_ALIGNED(size))
		return -EFAULT;

	user_addr = LOS_MMap(0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (IS_ERR_OR_NULL(user_addr)) {
		tloge("vm mmap failed\n");
		return user_addr;
	}

	for (int i = 0; i < (size >> PAGE_SHIFT); i++) {
		LosVmPage *page = LOS_VmPageGet(buffer + PAGE_SIZE * i);
		if (page == NULL) {
			goto err_out;
		}
		LOS_AtomicInc(&page->refCounts);
	}

	ret = remap_pfn_range(user_addr, buffer >> PAGE_SHIFT, size,
		VM_MAP_REGION_FLAG_PERM_USER | VM_MAP_REGION_FLAG_PERM_READ | VM_MAP_REGION_FLAG_PERM_WRITE);
	if (ret) {
		tloge("remap agent buffer failed, err=%d", ret);
		goto err_out;
	}

	return user_addr;
err_out:
	if (LOS_UnMMap(user_addr, size))
		tloge("munmap failed\n");
	return -EFAULT;
}

static bool is_valid_agent(unsigned int agent_id,
	unsigned int buffer_size, bool user_agent)
{
	if ((tc_ns_get_uid() != TEECD_UID) &&
		check_ext_agent_access(OsCurrTaskGet(), agent_id)) {
		tloge("It is a fake tee agent\n");
		return false;
	}

	if (user_agent && (buffer_size > SZ_4K)) {
		tloge("size: %u of user agent's shared mem is invalid\n",
			buffer_size);
		return false;
	}

	return true;
}

void clean_agent_pid_info(struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *agent_node = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry(agent_node, &g_agent_control.agent_list, head) {
		if (agent_node->owner == dev_file)
			agent_node->pid = 0;
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
}

static int is_agent_already_exist(unsigned int agent_id,
	struct smc_event_data **event_data, bool *find_flag)
{
	unsigned long flags;
	bool flag = false;
	struct smc_event_data *agent_node = NULL;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry(agent_node, &g_agent_control.agent_list, head) {
		if (agent_node->agent_id == agent_id) {
			if (agent_node->pid == OsCurrTaskGet()->processID) {
				tloge("no allow agent proc to reg twice\n");
				spin_unlock_irqrestore(&g_agent_control.lock, flags);
				return -EINVAL;
			}
			flag = true;
			get_agent_event(agent_node);
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
	*find_flag = flag;
	if (flag)
		*event_data = agent_node;
	return 0;
}

static void add_event_node_to_list(struct smc_event_data *event_data)
{
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_add_tail(&event_data->head, &g_agent_control.agent_list);
	atomic_set(&event_data->usage, 1);
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
}

static int register_agent_to_tee(unsigned int agent_id, const uintptr_t agent_buff,
	uint32_t agent_buff_size)
{
	int ret = 0;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	struct mb_cmd_pack *mb_pack = NULL;

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mailbox failed\n");
		return -ENOMEM;
	}

	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INPUT << TEE_PARAM_NUM);
	mb_pack->operation.params[0].value.a =
		virt_to_phys((void *)agent_buff);
	mb_pack->operation.params[0].value.b = 0;
	mb_pack->operation.params[1].value.a = agent_buff_size;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_REGISTER_AGENT;
	smc_cmd.operation_phys = virt_to_phys(&mb_pack->operation);
	smc_cmd.operation_h_phys = 0;
	smc_cmd.agent_id = agent_id;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("register agent to tee failed\n");
	}
	mailbox_free(mb_pack);

	return ret;
}

static int get_agent_buffer(struct smc_event_data *event_data,
	bool user_agent, void **buffer)
{
	/* agent first start or restart, both need a remap */
	if (user_agent) {
		event_data->agent_buff_user =
			(void *)(uintptr_t)agent_buffer_map(
			virt_to_phys(event_data->agent_buff_kernel),
			event_data->agent_buff_size);
		if (IS_ERR_OR_NULL(event_data->agent_buff_user)) {
			tloge("vm map agent buffer failed\n");
			return -EFAULT;
		}
		*buffer = event_data->agent_buff_user;
	} else {
		*buffer = event_data->agent_buff_kernel;
	}

	return 0;
}

int tc_ns_register_agent(struct tc_ns_dev_file *dev_file,
	unsigned int agent_id, unsigned int buffer_size,
	void **buffer, bool user_agent)
{
	struct smc_event_data *event_data = NULL;
	int ret = -EINVAL;
	bool find_flag = false;
	uintptr_t agent_buff = (uintptr_t)NULL;
	uint32_t size_align;

	/* dev can be null */
	if (!buffer)
		return ret;

	if (!is_valid_agent(agent_id, buffer_size, user_agent))
		return ret;

	size_align = ALIGN(buffer_size, SZ_4K);

	if (is_agent_already_exist(agent_id, &event_data, &find_flag))
		return ret;
	/*
	 * We find the agent event_data aready in agent_list, it indicate agent
	 * didn't unregister normally, so the event_data will be reused.
	 */
	if (find_flag) {
		init_restart_agent_node(dev_file, event_data);
	} else {
		ret = create_new_agent_node(dev_file, &event_data,
			agent_id, &agent_buff, size_align);
		if (ret)
			return ret;
	}

	if (get_agent_buffer(event_data, user_agent, buffer))
		goto release_rsrc;

	/* find_flag is false means it's a new agent register */
	if (!find_flag) {
		/*
		 * Obtain share memory which is released
		 * in tc_ns_unregister_agent
		 */
		ret = register_agent_to_tee(agent_id, agent_buff, size_align);
		if (ret) {
			unmap_agent_buffer(event_data);
			goto release_rsrc;
		}
		add_event_node_to_list(event_data);
	}
	if (find_flag)
		put_agent_event(event_data); /* match get action */
	return 0;

release_rsrc:
	if (find_flag)
		put_agent_event(event_data); /* match get action */
	else
		kfree(event_data); /* here event_data can never be NULL */

	if (agent_buff)
		mailbox_free((void *)agent_buff);
	return ret;
}

static int check_for_unregister_agent(unsigned int agent_id)
{
	bool check_value = false;

	if ((tc_ns_get_uid() != TEECD_UID) && tc_ns_get_uid() != SYSTEM_UID) {
		tloge("It is a fake tee agent\n");
		return -EINVAL;
	}

	check_value = is_built_in_agent(agent_id);

	if (check_value) {
		tloge("agent: 0x%x is not allowed to unregister\n", agent_id);
		return -EINVAL;
	}

	return 0;
}

bool __attribute__((weak)) is_third_party_agent(unsigned int agent_id)
{
	(void)agent_id;

	return false;
}

int tc_ns_unregister_agent(unsigned int agent_id)
{
	struct smc_event_data *event_data = NULL;
	int ret = 0;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	struct mb_cmd_pack *mb_pack = NULL;

	if (check_for_unregister_agent(agent_id))
		return -EINVAL;
	/*
	 * if third party itself trigger unregister agent
	 * we allow them to unregister.
	 */
	if (!is_third_party_agent(agent_id)) {
		tloge("invalid agent id: 0x%x\n", agent_id);
		return -EACCES;
	}

	event_data = find_event_control(agent_id);
	if (!event_data || !event_data->agent_buff_kernel) {
		tloge("agent is not found or kaddr is not allocated\n");
		return -EINVAL;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mailbox failed\n");
		put_agent_event(event_data);
		return -ENOMEM;
	}
	mb_pack->operation.paramtypes = TEE_PARAM_TYPE_VALUE_INPUT |
		(TEE_PARAM_TYPE_VALUE_INPUT << TEE_PARAM_NUM);
	mb_pack->operation.params[0].value.a =
		virt_to_phys(event_data->agent_buff_kernel);
	mb_pack->operation.params[0].value.b = 0;
	mb_pack->operation.params[1].value.a = SZ_4K;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_UNREGISTER_AGENT;
	smc_cmd.operation_phys = virt_to_phys(&mb_pack->operation);
	smc_cmd.operation_h_phys = 0;
	smc_cmd.agent_id = agent_id;
	tlogd("unregistering agent 0x%x\n", agent_id);

	if (!tc_ns_smc(&smc_cmd)) {
		free_event_control(agent_id);
	} else {
		ret = -EPERM;
		tloge("unregister agent failed\n");
	}
	put_agent_event(event_data);
	mailbox_free(mb_pack);
	return ret;
}

bool is_system_agent(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	bool system_agent = false;
	unsigned long flags;

	if (!dev_file)
		return system_agent;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file) {
			system_agent = true;
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	return system_agent;
}

void send_crashed_event_response_all(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	unsigned int agent_id[AGENT_MAX] = {0};
	unsigned int i = 0;
	unsigned long flags;

	if (!dev_file)
		return;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file && i < AGENT_MAX)
			agent_id[i++] = event_data->agent_id;
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);

	for (i = 0; i < AGENT_MAX; i++) {
		if (agent_id[i])
			send_event_response(agent_id[i]);
	}

	return;
}

void tee_agent_clear_dev_owner(const struct tc_ns_dev_file *dev_file)
{
	struct smc_event_data *event_data = NULL;
	struct smc_event_data *tmp = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_agent_control.lock, flags);
	list_for_each_entry_safe(event_data, tmp, &g_agent_control.agent_list,
		head) {
		if (event_data->owner == dev_file) {
			event_data->owner = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&g_agent_control.lock, flags);
}


static int def_tee_agent_work(uintptr_t instance, int len)
{
	int ret = 0;
	struct tee_agent_kernel_ops *agent_instance = NULL;

	agent_instance = (void *)instance;
	while (!kthread_should_stop()) {
		tlogd("%s agent loop++++\n", agent_instance->agent_name);
		ret = tc_ns_wait_event(agent_instance->agent_id);
		if (ret) {
			tloge("%s wait event fail\n",
				agent_instance->agent_name);
			break;
		}
		if (agent_instance->tee_agent_work) {
			ret = agent_instance->tee_agent_work(agent_instance);
			if (ret)
				tloge("%s agent work fail\n",
					agent_instance->agent_name);
		}
		ret = tc_ns_send_event_response(agent_instance->agent_id);
		if (ret) {
			tloge("%s send event response fail\n",
				agent_instance->agent_name);
			break;
		}
		tlogd("%s agent loop----\n", agent_instance->agent_name);
	}

	return ret;
}

static int def_tee_agent_run(struct tee_agent_kernel_ops *agent_instance)
{
	struct tc_ns_dev_file dev = {0};
	int ret;
	char agent_name[OS_TCB_NAME_LEN] = {0};

	/* 1. Register agent buffer to TEE */
	ret = tc_ns_register_agent(&dev, agent_instance->agent_id,
		agent_instance->agent_buff_size, &agent_instance->agent_buff,
		false);
	if (ret) {
		tloge("register agent buffer fail,ret =0x%x\n", ret);
		ret = -EINVAL;
		goto out;
	}

	/* 2. Creat thread to run agent */
	ret = sprintf_s(agent_name, OS_TCB_NAME_LEN, "agent_%s", agent_instance->agent_name);
	if (ret == -1)
		goto out;
	agent_instance->agent_thread =
		kthread_run(def_tee_agent_work, agent_instance,
			sizeof(struct tee_agent_kernel_ops), (char *)agent_instance->agent_name);
	if (IS_ERR_OR_NULL(agent_instance->agent_thread)) {
		tloge("kthread creat fail\n");
		ret = PTR_ERR(agent_instance->agent_thread);
		agent_instance->agent_thread = NULL;
		goto out;
	}
	return 0;

out:
	return ret;
}

static int def_tee_agent_stop(struct tee_agent_kernel_ops *agent_instance)
{
	int ret;

	if (tc_ns_send_event_response(agent_instance->agent_id))
		tloge("failed to send response for agent %u\n",
			agent_instance->agent_id);
	ret = tc_ns_unregister_agent(agent_instance->agent_id);
	if (ret)
		tloge("failed to unregister agent %u\n",
			agent_instance->agent_id);
	if (!IS_ERR_OR_NULL(agent_instance->agent_thread))
		kthread_stop(agent_instance->agent_thread);

	return 0;
}

static struct tee_agent_kernel_ops g_def_tee_agent_ops = {
	.agent_name = "default",
	.agent_id = 0,
	.tee_agent_init = NULL,
	.tee_agent_run = def_tee_agent_run,
	.tee_agent_work = NULL,
	.tee_agent_exit = NULL,
	.tee_agent_stop = def_tee_agent_stop,
	.tee_agent_crash_work = NULL,
	.agent_buff_size = PAGE_SIZE,
	.list = LINUX_LIST_HEAD_INIT(g_def_tee_agent_ops.list)
};

static int tee_agent_kernel_init(void)
{
	struct tee_agent_kernel_ops *agent_ops = NULL;
	int ret = 0;

	list_for_each_entry(agent_ops, &g_tee_agent_list, list) {
		/* Check the agent validity */
		if (!agent_ops->agent_id ||
			!agent_ops->agent_name ||
			!agent_ops->tee_agent_work) {
			tloge("agent is invalid\n");
			continue;
		}
		tlogd("ready to init %s agent, id=0x%x\n",
			agent_ops->agent_name, agent_ops->agent_id);

		/* Set agent buff size */
		if (!agent_ops->agent_buff_size)
			agent_ops->agent_buff_size =
				g_def_tee_agent_ops.agent_buff_size;

		/* Initialize the agent */
		if (agent_ops->tee_agent_init)
			ret = agent_ops->tee_agent_init(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_init)
			ret = g_def_tee_agent_ops.tee_agent_init(agent_ops);
		else
			tlogw("agent id %u has no init function\n",
				agent_ops->agent_id);
		if (ret) {
			tloge("tee_agent_init %s failed\n",
				agent_ops->agent_name);
			continue;
		}

		/* Run the agent */
		if (agent_ops->tee_agent_run)
			ret = agent_ops->tee_agent_run(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_run)
			ret = g_def_tee_agent_ops.tee_agent_run(agent_ops);
		else
			tlogw("agent id %u has no run function\n",
				agent_ops->agent_id);

		if (ret) {
			tloge("tee_agent_run %s failed\n",
				agent_ops->agent_name);
			if (agent_ops->tee_agent_exit)
				agent_ops->tee_agent_exit(agent_ops);
			continue;
		}
	}

	return 0;
}

static void tee_agent_kernel_exit(void)
{
	struct tee_agent_kernel_ops *agent_ops = NULL;

	list_for_each_entry(agent_ops, &g_tee_agent_list, list) {
		/* Stop the agent */
		if (agent_ops->tee_agent_stop)
			agent_ops->tee_agent_stop(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_stop)
			g_def_tee_agent_ops.tee_agent_stop(agent_ops);
		else
			tlogw("agent id %u has no stop function\n",
				agent_ops->agent_id);

		/* Uninitialize the agent */
		if (agent_ops->tee_agent_exit)
			agent_ops->tee_agent_exit(agent_ops);
		else if (g_def_tee_agent_ops.tee_agent_exit)
			g_def_tee_agent_ops.tee_agent_exit(agent_ops);
		else
			tlogw("agent id %u has no exit function\n",
				agent_ops->agent_id);
	}
}

int tee_agent_clear_work(struct tc_ns_client_context *context,
	unsigned int dev_file_id)
{
	struct tee_agent_kernel_ops *agent_ops = NULL;

	list_for_each_entry(agent_ops, &g_tee_agent_list, list) {
		if (agent_ops->tee_agent_crash_work)
			agent_ops->tee_agent_crash_work(agent_ops,
				context, dev_file_id);
	}
	return 0;
}

int tee_agent_kernel_register(struct tee_agent_kernel_ops *new_agent)
{
	if (!new_agent)
		return -EINVAL;

	INIT_LIST_HEAD(&new_agent->list);
	list_add_tail(&new_agent->list, &g_tee_agent_list);

	return 0;
}

void agent_init(void)
{
	spin_lock_init(&g_agent_control.lock);
	INIT_LIST_HEAD(&g_agent_control.agent_list);
	INIT_LIST_HEAD(&g_tee_agent_list);

	if (tee_agent_kernel_init())
		tloge("tee agent kernel init failed\n");
	return;
}

int agent_exit(void)
{
	tee_agent_kernel_exit();
	return 0;
}
