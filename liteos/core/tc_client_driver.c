/*
 * tc_client_driver.c
 *
 * function for proc open,close session and invoke
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
#include "tc_client_driver.h"
#include <securec.h>
#include "smc_smp.h"
#include "teek_client_constants.h"
#include "agent.h"
#include "mem.h"
#include "gp_ops.h"
#include "tc_ns_log.h"
#include "tc_ns_client.h"
#include "mailbox_mempool.h"
#include "tz_spi_notify.h"
#include "auth_base_impl.h"
#include "client_hash_auth.h"
#include "auth_base_impl.h"
#include "tlogger.h"
#include "tzdebug.h"
#include "session_manager.h"
#include "los_adapt.h"

struct workqueue_struct *g_tzdriver_wq = NULL;

#ifdef CONFIG_ACPI
static int g_acpi_irq;
#endif

static unsigned int g_device_file_cnt = 1;
static mutex_t g_device_file_cnt_lock = PTHREAD_MUTEX_INITIALIZER;

/* dev node list and itself has mutex to avoid race */
struct tc_ns_dev_list g_tc_ns_dev_list;

struct tc_ns_dev_list *get_dev_list(void)
{
	return &g_tc_ns_dev_list;
}

static int tc_ns_get_tee_version(const struct tc_ns_dev_file *dev_file,
	void __user *argp)
{
	unsigned int version;
	struct tc_ns_smc_cmd smc_cmd = { {0}, 0 };
	int ret = 0;
	struct mb_cmd_pack *mb_pack = NULL;
	if (!argp) {
		tloge("error input parameter\n");
		return -EINVAL;
	}

	mb_pack = mailbox_alloc_cmd_pack();
	if (!mb_pack) {
		tloge("alloc mb pack failed\n");
		return -ENOMEM;
	}

	mb_pack->operation.paramtypes = TEEC_VALUE_OUTPUT;
	smc_cmd.cmd_type = CMD_TYPE_GLOBAL;
	smc_cmd.cmd_id = GLOBAL_CMD_ID_GET_TEE_VERSION;
	smc_cmd.dev_file_id = dev_file->dev_file_id;
	smc_cmd.operation_phys = virt_to_phys(&mb_pack->operation);
	smc_cmd.operation_h_phys = 0;

	if (tc_ns_smc(&smc_cmd)) {
		ret = -EPERM;
		tloge("smc call returns error ret 0x%x\n", smc_cmd.ret_val);
	}

	version = mb_pack->operation.params[0].value.a;
	if (copy_to_user(argp, &version, sizeof(unsigned int)))
		ret = -EFAULT;
	mailbox_free(mb_pack);

	return ret;
}

/*
 * This is the login information
 * and is set teecd when client opens a new session
 */
#define MAX_BUF_LEN 4096

static int get_pack_name_len(struct tc_ns_dev_file *dev_file,
	const uint8_t *cert_buffer)
{
	if (memcpy_s(&dev_file->pkg_name_len, sizeof(dev_file->pkg_name_len),
		cert_buffer, sizeof(dev_file->pkg_name_len)))
		return -EFAULT;

	if (!dev_file->pkg_name_len ||
		dev_file->pkg_name_len >= MAX_PACKAGE_NAME_LEN) {
		tloge("invalid pack name len: %u\n", dev_file->pkg_name_len);
		return -EINVAL;
	}

	tlogd("package name len is %u\n", dev_file->pkg_name_len);

	return 0;
}

static int get_public_key_len(struct tc_ns_dev_file *dev_file,
	const uint8_t *cert_buffer)
{
	if (memcpy_s(&dev_file->pub_key_len, sizeof(dev_file->pub_key_len),
		cert_buffer, sizeof(dev_file->pub_key_len)))
		return -EFAULT;

	if (dev_file->pub_key_len > MAX_PUBKEY_LEN) {
		tloge("invalid public key len: %u\n", dev_file->pub_key_len);
		return -EINVAL;
	}

	tlogd("publick key len is %u\n", dev_file->pub_key_len);

	return 0;
}

static int get_public_key(struct tc_ns_dev_file *dev_file,
	const uint8_t *cert_buffer)
{
	/* get public key */
	if (!dev_file->pub_key_len)
		return 0;

	if (memcpy_s(dev_file->pub_key, MAX_PUBKEY_LEN, cert_buffer,
		dev_file->pub_key_len)) {
		tloge("failed to copy pub key len\n");
		return -EINVAL;
	}

	return 0;
}

static bool is_cert_buffer_size_valid(int cert_buffer_size)
{
	/*
	 * GET PACKAGE NAME AND APP CERTIFICATE:
	 * The proc_info format is as follows:
	 * package_name_len(4 bytes) || package_name ||
	 * apk_cert_len(4 bytes) || apk_cert.
	 * or package_name_len(4 bytes) || package_name
	 * || exe_uid_len(4 bytes) || exe_uid.
	 * The apk certificate format is as follows:
	 * modulus_size(4bytes) ||modulus buffer
	 * || exponent size || exponent buffer
	 */
	if (cert_buffer_size > MAX_BUF_LEN || !cert_buffer_size) {
		tloge("cert buffer size is invalid!\n");
		return false;
	}

	return true;
}

static int alloc_login_buf(struct tc_ns_dev_file *dev_file,
	uint8_t **cert_buffer, unsigned int *cert_buffer_size)
{
	*cert_buffer_size = (unsigned int)(MAX_PACKAGE_NAME_LEN +
		MAX_PUBKEY_LEN + sizeof(dev_file->pkg_name_len) +
		sizeof(dev_file->pub_key_len));

	*cert_buffer = kmalloc(*cert_buffer_size, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)(*cert_buffer))) {
		tloge("failed to allocate login buffer!");
		return -ENOMEM;
	}

	return 0;
}

static int client_login_prepare(uint8_t *cert_buffer,
	const void __user *buffer, unsigned int cert_buffer_size)
{
	if (!is_cert_buffer_size_valid(cert_buffer_size))
		return -EINVAL;

	if (copy_from_user(cert_buffer, buffer, cert_buffer_size)) {
		tloge("Failed to get user login info!\n");
		return -EINVAL;
	}

	return 0;
}

static int tc_ns_client_login_func_without_cert(struct tc_ns_dev_file *dev_file)
{
	int ret;
	uint8_t *cert_buffer = NULL;
	uint8_t *temp_cert_buffer = NULL;
	unsigned int cert_buffer_size = 0;
	char *path = NULL;
	errno_t sret;

	if (!dev_file)
		return -EINVAL;

	mutex_lock(&dev_file->login_setup_lock);

	if (dev_file->login_setup) {
		tloge("login information cannot be set twice!\n");
		mutex_unlock(&dev_file->login_setup_lock);
		return -EINVAL;
	}

	ret = alloc_login_buf(dev_file, &cert_buffer,
		&cert_buffer_size);
	if (ret != 0) {
		tloge("alloc fail\n");
		goto error;
	}
	temp_cert_buffer = cert_buffer;
	path = get_process_path(OsCurrTaskGet(), (char *)cert_buffer, MAX_PACKAGE_NAME_LEN);
	if (path == NULL) {
		tloge("get path fail\n");
		ret = -EFAULT;
		goto error;
	}
	dev_file->pkg_name_len = strlen(path);
	sret = strncpy_s((char *)dev_file->pkg_name, MAX_PACKAGE_NAME_LEN, (char *)cert_buffer, dev_file->pkg_name_len);
	if (sret != EOK) {
		tloge("str cpy fail\n");
		ret = -ENOMEM;
		goto error;
	}

	int uid = get_task_uid(OsCurrTaskGet());
	dev_file->pub_key_len = sizeof(uid);
	if (memcpy_s((char *)dev_file->pub_key, MAX_PUBKEY_LEN, (char *)&uid, dev_file->pub_key_len)) {
		tloge("failed to copy cert, pubkeylen = %u\n", dev_file->pub_key_len);
		ret = -EINVAL;
		goto error;
	}

	dev_file->login_setup = true;

error:
	kfree(temp_cert_buffer);
	mutex_unlock(&dev_file->login_setup_lock);
	return ret;
}

static int tc_ns_client_login_func_with_cert(struct tc_ns_dev_file *dev_file,
	const void __user *buffer)
{
	int ret;
	uint8_t *cert_buffer = NULL;
	uint8_t *temp_cert_buffer = NULL;
	unsigned int cert_buffer_size = 0;

	if (!dev_file)
		return -EINVAL;

	if (!buffer) {
		/*
		 * We accept no debug information
		 * because the daemon might  have failed
		 */
		dev_file->pkg_name_len = 0;
		dev_file->pub_key_len = 0;
		return 0;
	}

	mutex_lock(&dev_file->login_setup_lock);
	if (dev_file->login_setup) {
		tloge("login information cannot be set twice!\n");
		mutex_unlock(&dev_file->login_setup_lock);
		return -EINVAL;
	}

	ret = alloc_login_buf(dev_file, &cert_buffer, &cert_buffer_size);
	if (ret) {
		mutex_unlock(&dev_file->login_setup_lock);
		return ret;
	}

	temp_cert_buffer = cert_buffer;
	if (client_login_prepare(cert_buffer, buffer, cert_buffer_size)) {
		ret = -EINVAL;
		goto error;
	}

	ret = get_pack_name_len(dev_file, cert_buffer);
	if (ret)
		goto error;
	cert_buffer += sizeof(dev_file->pkg_name_len);

	if (strncpy_s((char *)dev_file->pkg_name, MAX_PACKAGE_NAME_LEN, (char *)cert_buffer,
		dev_file->pkg_name_len)) {
		ret = -ENOMEM;
		goto error;
	}
	cert_buffer += dev_file->pkg_name_len;

	ret = get_public_key_len(dev_file, cert_buffer);
	if (ret)
		goto error;
	cert_buffer += sizeof(dev_file->pub_key_len);

	ret = get_public_key(dev_file, cert_buffer);
	dev_file->login_setup = true;

error:
	kfree(temp_cert_buffer);
	mutex_unlock(&dev_file->login_setup_lock);
	return ret;
}

static int tc_ns_client_login_func(struct tc_ns_dev_file *dev_file,
	const void __user *buffer)
{
	if (buffer == NULL)
		return tc_ns_client_login_func_without_cert(dev_file);
	else
		return tc_ns_client_login_func_with_cert(dev_file, buffer);
}

int tc_ns_client_open(struct tc_ns_dev_file **dev_file, uint8_t kernel_api)
{
	struct tc_ns_dev_file *dev = NULL;

	tlogd("tc_client_open\n");
	if (!dev_file) {
		tloge("dev_file is NULL\n");
		return -EINVAL;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR((unsigned long)(uintptr_t)dev)) {
		tloge("dev malloc failed\n");
		return -ENOMEM;
	}

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_add_tail(&dev->head, &g_tc_ns_dev_list.dev_file_list);
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);
	mutex_lock(&g_device_file_cnt_lock);
	dev->dev_file_id = g_device_file_cnt;
	g_device_file_cnt++;
	mutex_unlock(&g_device_file_cnt_lock);
	INIT_LIST_HEAD(&dev->shared_mem_list);
	dev->login_setup = 0;
	dev->kernel_api = kernel_api;
	dev->load_app_flag = 0;
	mutex_init(&dev->service_lock);
	mutex_init(&dev->shared_mem_lock);
	mutex_init(&dev->login_setup_lock);
	*dev_file = dev;

	return 0;
}

static void del_dev_node(struct tc_ns_dev_file *dev)
{
	if (!dev)
		return;

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_del(&dev->head);
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);
}

void free_dev(struct tc_ns_dev_file *dev)
{
	del_dev_node(dev);
	tee_agent_clear_dev_owner(dev);
	if (memset_s(dev, sizeof(*dev), 0, sizeof(*dev)))
		tloge("Caution, memset dev fail!\n");
	kfree(dev);
}

int tc_ns_client_close(struct tc_ns_dev_file *dev)
{
	if (!dev) {
		tloge("invalid dev(null)\n");
		return -EINVAL;
	}

	close_unclosed_session_in_kthread(dev);

	/* for thirdparty agent, code runs here only when agent crashed */
	send_crashed_event_response_all(dev);
	free_dev(dev);

	return 0;
}

static void release_vma_shared_mem(struct tc_ns_dev_file *dev_file,
	const LosVmMapRegion *vma)
{
	struct tc_ns_shared_mem *shared_mem = NULL;
	struct tc_ns_shared_mem *shared_mem_temp = NULL;
	bool find = false;

	mutex_lock(&dev_file->shared_mem_lock);
	list_for_each_entry_safe(shared_mem, shared_mem_temp,
			&dev_file->shared_mem_list, head) {
		if (shared_mem) {
			if (shared_mem->user_addr ==
				(void *)(uintptr_t)vma->range.base) {
				shared_mem->user_addr = NULL;
				find = true;
			} else if (shared_mem->user_addr_ca ==
				(void *)(uintptr_t)vma->range.base) {
				shared_mem->user_addr_ca = NULL;
				find = true;
			}

			if (!shared_mem->user_addr &&
				!shared_mem->user_addr_ca)
				list_del(&shared_mem->head);

			/* pair with tc client mmap */
			if (find) {
				put_sharemem_struct(shared_mem);
				break;
			}
		}
	}
	mutex_unlock(&dev_file->shared_mem_lock);
}

static int shared_vma_close(struct tc_ns_dev_file *dev_file, const unsigned int argp)
{
	if (dev_file == NULL) {
		tloge("unmap input error\n");
		return -EINVAL;
	}

	LosVmMapRegion *vma = LOS_RegionFind(OsCurrProcessGet()->vmSpace, (vaddr_t)argp);
	if (!vma) {
		tloge("vma is null\n");
		return -EINVAL;
	}

	release_vma_shared_mem(dev_file, vma);
	return 0;
}

static struct tc_ns_shared_mem *find_sharedmem(
	const LosVmMapRegion *vma,
	const struct tc_ns_dev_file *dev_file, bool *only_remap)
{
	struct tc_ns_shared_mem *shm_tmp = NULL;
	unsigned long len = vma->range.size;

	/*
	 * using vma->vm_pgoff as share_mem index
	 * check if aready allocated
	 */
	list_for_each_entry(shm_tmp, &dev_file->shared_mem_list, head) {
		if (atomic_read(&shm_tmp->offset) == vma->pgOff) {
			tlogd("sharemem already alloc, shm tmp->offset=%d\n",
				atomic_read(&shm_tmp->offset));
			/*
			 * args check:
			 * 1. this shared mem is already mapped
			 * 2. remap a different size shared_mem
			 */
			if (shm_tmp->user_addr_ca ||
				vma->range.size != shm_tmp->len) {
				tloge("already remap once!\n");
				return NULL;
			}
			/* return the same sharedmem specified by vm_pgoff */
			*only_remap = true;
			get_sharemem_struct(shm_tmp);
			return shm_tmp;
		}
	}

	/* if not find, alloc a new sharemem */
	return tc_mem_allocate(len);
}

static int remap_shared_mem(LosVmMapRegion *vma,
	const struct tc_ns_shared_mem *shared_mem)
{
	int ret;

	ret = remap_vmalloc_range(vma, shared_mem->kernel_addr, 0);
	if (ret)
		tloge("can't remap to user, ret = %d\n", ret);

	return ret;
}

/*
 * in this func, we need to deal with follow cases:
 * vendor CA alloc sharedmem (alloc and remap);
 * HIDL alloc sharedmem (alloc and remap);
 * system CA alloc sharedmem (only just remap);
 */
static int tc_client_mmap(struct file *filp, LosVmMapRegion *vma)
{
	int ret;
	struct tc_ns_dev_file *dev_file = NULL;
	struct tc_ns_shared_mem *shared_mem = NULL;
	bool only_remap = false;

	if (!filp || !vma || !filp->f_priv) {
		tloge("invalid args for tc mmap\n");
		return -EINVAL;
	}
	dev_file = filp->f_priv;

	mutex_lock(&dev_file->shared_mem_lock);
	shared_mem = find_sharedmem(vma, dev_file, &only_remap);
	if (IS_ERR_OR_NULL(shared_mem)) {
		tloge("alloc shared mem failed\n");
		mutex_unlock(&dev_file->shared_mem_lock);
		return -ENOMEM;
	}

	ret = remap_shared_mem(vma, shared_mem);
	if (ret) {
		if (only_remap)
			put_sharemem_struct(shared_mem);
		else
			tc_mem_free(shared_mem);
		mutex_unlock(&dev_file->shared_mem_lock);
		return ret;
	}

	if (only_remap) {
		shared_mem->user_addr_ca = (void *)vma->range.base;
		mutex_unlock(&dev_file->shared_mem_lock);
		return ret;
	}
	shared_mem->user_addr = (void *)vma->range.base;
	atomic_set(&shared_mem->offset, vma->pgOff);
	get_sharemem_struct(shared_mem);
	list_add_tail(&shared_mem->head, &dev_file->shared_mem_list);
	mutex_unlock(&dev_file->shared_mem_lock);

	return ret;
}

static int ioctl_register_agent(struct tc_ns_dev_file *dev_file, unsigned long arg)
{
	int ret;
	struct agent_ioctl_args args;

	if (!arg) {
		tloge("arg is NULL\n");
		return -EFAULT;
	}

	if (copy_from_user(&args, (void *)(uintptr_t)arg, sizeof(args))) {
		tloge("copy agent args failed\n");
		return -EFAULT;
	}

	ret = tc_ns_register_agent(dev_file, args.id, args.buffer_size,
		&args.buffer, true);
	if (!ret) {
		if (copy_to_user((void *)(uintptr_t)arg, &args, sizeof(args)))
			tloge("copy agent user addr failed\n");
	}

	return ret;
}

static int ioctl_unregister_agent(const struct tc_ns_dev_file *dev_file,
	unsigned long arg)
{
	int ret;
	struct smc_event_data *event_data = NULL;

	event_data = find_event_control((unsigned int)arg);
	if (!event_data) {
		tloge("invalid agent id\n");
		return -EINVAL;
	}

	if (event_data->owner != dev_file) {
		tloge("invalid unregister request\n");
		put_agent_event(event_data);
		return -EINVAL;
	}

	put_agent_event(event_data);
	ret = tc_ns_unregister_agent((unsigned int)arg);

	return ret;
}

/* ioctls for the secure storage daemon */
static long public_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	struct tc_ns_dev_file *dev_file = file->f_priv;
	void *argp = (void __user *)(uintptr_t)arg;

	if (!dev_file) {
		tloge("invalid params\n");
		return -EINVAL;
	}

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_WAIT_EVENT:
		ret = tc_ns_wait_event((unsigned int)arg);
		break;
	case TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE:
		ret = tc_ns_send_event_response((unsigned int)arg);
		break;
	case TC_NS_CLIENT_IOCTL_REGISTER_AGENT:
		ret = ioctl_register_agent(dev_file, arg);
		break;
	case TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT:
		ret = ioctl_unregister_agent(dev_file, arg);
		break;
	case TC_NS_CLIENT_IOCTL_LOAD_APP_REQ:
		ret = tc_ns_load_secfile(dev_file, argp);
	break;
	default:
		tloge("invalid cmd! 0x%x\n", cmd);
		break;
	}
	return ret;
}

static int tc_ns_send_cancel_cmd(struct tc_ns_dev_file *dev_file,
	void *argp, struct tc_ns_client_context *client_context)
{
	if (!argp) {
		tloge("argp is NULL input buffer\n");
		return -EINVAL;
	}
	if (copy_from_user(client_context, argp, sizeof(*client_context))) {
		tloge("copy from user failed\n");
		return -ENOMEM;
	}

	client_context->returns.code = TEEC_ERROR_GENERIC;
	client_context->returns.origin = TEEC_ORIGIN_COMMS;
	tloge("not support send cancle cmd now\n");
	if (copy_to_user(argp, client_context, sizeof(*client_context)))
		return -EFAULT;

	return 0;
}

uint32_t tc_ns_get_uid(void)
{
	return get_task_uid(OsCurrTaskGet());
}

static long tc_private_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_SET_NATIVE_IDENTITY:
		ret = tc_ns_set_native_hash(arg, GLOBAL_CMD_ID_SET_CA_HASH);
		break;
	case TC_NS_CLIENT_IOCTL_LATEINIT:
		ret = tc_ns_late_init(arg);
		break;
	case TC_NS_CLIENT_IOCTL_SYC_SYS_TIME:
		ret = tc_ns_sync_sys_time(
			(struct tc_ns_client_time *)(uintptr_t)arg);
		break;
	default:
		ret = public_ioctl(file, cmd, arg);
		break;
	}
	return ret;
}

static int get_agent_id(int cmd, unsigned long arg, uint32_t *agent_id)
{
	struct agent_ioctl_args args;
	int ret = 0;
	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_WAIT_EVENT:
	case TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE:
	case TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT:
		*agent_id = (unsigned int)arg;
		break;
	case TC_NS_CLIENT_IOCTL_REGISTER_AGENT:
		if (!arg) {
			tloge("arg is NULL\n");
			ret = -EFAULT;
			break;
		}
		if (copy_from_user(&args, (void *)(uintptr_t)arg, sizeof(args))) {
			tloge("copy from user failed\n");
			ret = -EFAULT;
			break;
		}
		*agent_id = args.id;
		break;
	default:
		tloge("invalid cmd! 0x%x\n", cmd);
		break;
	}
	return ret;
}

static int tc_client_agent_ioctl(struct file *file, int cmd,
	unsigned long arg)
{
	unsigned int agent_id = 0;
	int ret = -EFAULT;
	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_WAIT_EVENT:
	case TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE:
	case TC_NS_CLIENT_IOCTL_REGISTER_AGENT:
	case TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT:
		if (get_agent_id(cmd, arg, &agent_id)) {
			tloge("can not get agent id\n");
			return -EFAULT;
		}
		if (check_ext_agent_access(OsCurrTaskGet(), agent_id)) {
			tloge("the agent id is not access\n");
			return -EFAULT;
		}
		ret = public_ioctl(file, cmd, arg);
		break;
	default:
		tloge("invalid cmd\n");
		break;
	}

	return ret;
}

static int tc_client_ioctl(struct file *file, int cmd,
	unsigned long arg)
{
	int ret = -EFAULT;
	void *argp = (void __user *)(uintptr_t)arg;
	struct tc_ns_dev_file *dev_file = file->f_priv;
	struct tc_ns_client_context client_context = {{0}};

	switch (cmd) {
	case TC_NS_CLIENT_IOCTL_SES_OPEN_REQ:
	case TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ:
	case TC_NS_CLIENT_IOCTL_SEND_CMD_REQ:
		ret = tc_client_session_ioctl(file, cmd, arg);
		break;
	case TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ:
		ret = tc_ns_send_cancel_cmd(dev_file, argp, &client_context);
		break;
	case TC_NS_CLIENT_IOCTL_LOGIN:
		ret = tc_ns_client_login_func(dev_file, argp);
		break;
	case TC_NS_CLIENT_IOCTL_TST_CMD_REQ:
		ret = tc_ns_tst_cmd(argp);
		break;
	case TC_NS_CLIENT_IOCTL_GET_TEE_VERSION:
		ret = tc_ns_get_tee_version(dev_file, argp);
		break;
	case TC_NS_CLIENT_IOCTL_UNMAP_SHARED_MEM:
		ret = shared_vma_close(file->f_priv, (unsigned int)(uintptr_t)argp);
		break;
	case TC_NS_CLIENT_IOCTL_LOAD_APP_REQ:
		ret = tc_ns_load_secfile(dev_file, argp);
		break;
	default:
		ret = tc_client_agent_ioctl(file, cmd, arg);
		break;
	}

	return ret;
}

static int tc_client_open(struct file *file)
{
	int ret;
	struct tc_ns_dev_file *dev = NULL;

	file->f_priv = NULL;
	ret = tc_ns_client_open(&dev, TEE_REQ_FROM_USER_MODE);
	if (!ret)
		file->f_priv = dev;

	return ret;
}

static int tc_client_close(struct file *file)
{
	int ret = 0;
	struct tc_ns_dev_file *dev = file->f_priv;

	clean_agent_pid_info(dev);
	/* for CA(HIDL thread) close fd */
	ret = tc_ns_client_close(dev);
	file->f_priv = NULL;

	return ret;
}

static int tc_private_close(struct file *file)
{
	int ret = 0;
	struct tc_ns_dev_file *dev = file->f_priv;

	clean_agent_pid_info(dev);
	/* for teecd close fd */
	tloge("teecd exit\n");
	if (is_system_agent(dev)) {
		/* for teecd agent close fd */
		send_event_response_single(dev);
		free_dev(dev);
	} else {
		/* for ca damon close fd */
		ret = free_dev(dev);
	}
	file->f_priv = NULL;

	return ret;
}

struct tc_ns_dev_file *tc_find_dev_file(unsigned int dev_file_id)
{
	struct tc_ns_dev_file *dev_file = NULL;

	mutex_lock(&g_tc_ns_dev_list.dev_lock);
	list_for_each_entry(dev_file, &g_tc_ns_dev_list.dev_file_list, head) {
		if (dev_file->dev_file_id == dev_file_id) {
			mutex_unlock(&g_tc_ns_dev_list.dev_lock);
			return dev_file;
		}
	}
	mutex_unlock(&g_tc_ns_dev_list.dev_lock);
	return NULL;
}

#ifdef CONFIG_COMPAT
long tc_compat_client_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	long ret;

	if (!file)
		return -EINVAL;

	arg = (unsigned long)(uintptr_t)compat_ptr(arg);
	ret = tc_client_ioctl(file, cmd, arg);
	return ret;
}
#endif

static const struct file_operations_vfs g_tc_ns_client_fops = {
	.open = tc_client_open,
	.close = tc_client_close,
	.ioctl = tc_client_ioctl,
	.mmap = tc_client_mmap,
};

static const struct file_operations_vfs g_tc_private_fops = {
	.open = tc_client_open,
	.close = tc_private_close,
	.ioctl = tc_private_ioctl,
};

bool schedule_work_on(int cpu, struct work_struct *work)
{
	return queue_work(g_tzdriver_wq, work);
}

static int tc_ns_client_init(void)
{
	int ret;

	tlogd("tc_ns_client_init");

	ret = create_tc_client_device(TC_NS_CLIENT_DEV_NAME, &g_tc_ns_client_fops);
	if (ret != EOK) {
		tloge("create tee device error.\n");
		return ret;
	}

	ret = create_tc_client_device(TC_PRIVATE_DEV_NAME, &g_tc_ns_client_fops);
	if (ret != EOK) {
		tloge("create tee device error.\n");
		return ret;
	}	
	ret = memset_s(&g_tc_ns_dev_list, sizeof(g_tc_ns_dev_list), 0,
		sizeof(g_tc_ns_dev_list));
	if (ret != EOK)
		goto destroy_dev;

	INIT_LIST_HEAD(&g_tc_ns_dev_list.dev_file_list);
	mutex_init(&g_tc_ns_dev_list.dev_lock);
	init_srvc_list();

	g_tzdriver_wq = create_workqueue("g_tzalloc_ordered_workqueuedriver_wq");
	if (g_tzdriver_wq == NULL) {
		tloge("create tzdriver workqueue failed\n");
		ret = -EFAULT;
		goto destroy_dev;
	}

	return ret;

destroy_dev:
	(void)unregister_driver(TC_NS_CLIENT_DEV_NAME);
	(void)unregister_driver(TC_PRIVATE_DEV_NAME);	
	return ret;
}

static int tc_teeos_init(void)
{
	int ret;
	ret = smc_context_init();
	if (ret)
		return ret;
	ret = mailbox_mempool_init();
	if (ret) {
		tloge("tz mailbox init failed\n");
		goto smc_data_free;
	}
	ret = tz_spi_init();
	if (ret)
		goto release_mailbox;

	return 0;
release_mailbox:
	mailbox_mempool_destroy();
smc_data_free:
	smc_free_data();
	return ret;
}

static void tc_re_init(void)
{
	int ret;

	agent_init();

	if (tzdebug_init())
		tloge("tzdebug init failed\n");

	ret = init_tlogger_service();
	if (ret)
		tloge("tlogger init failed\n");

#ifndef CONFIG_MINI_PLATFORM
	if (init_smc_svc_thread()) {
		tloge("init svc thread\n");
		ret = -EFAULT;
	}
#endif

	if (ret)
		tloge("Caution! Running environment init failed!\n");
}

__init int tc_init(void)
{
	int ret = 0;
	ret = tc_ns_client_init();
	if (ret)
		return ret;
	ret = tc_teeos_init();
	if (ret)
		goto class_device_destroy;
	/* run-time environment init failure don't block tzdriver init proc */
	tc_re_init();
	return 0;

class_device_destroy:
	(void)unregister_driver(TC_NS_CLIENT_DEV_NAME);
	(void)unregister_driver(TC_PRIVATE_DEV_NAME);
	if (g_tzdriver_wq != NULL)
		destroy_workqueue(g_tzdriver_wq);
	return ret;
}

#ifndef CONFIG_LITEOS_TZDRIVER
static void tc_exit(void)
{
	tlogd("tz client exit");
	tz_spi_exit();
	/* run-time environment exit should before teeos exit */
	smc_free_data();
	agent_exit();
#ifdef CONFIG_TZDRIVER_MODULE
	tzdebug_exit();
	exit_tlogger_service();
#endif
	mailbox_mempool_destroy();
	tee_exit_shash_handle();
}
#endif
