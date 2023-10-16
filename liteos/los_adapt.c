/*
 * los_adapt.c
 *
 * functions for liteos tzdriver
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

#include "los_adapt.h"
#include "mbedtls/aes.h"
#include "tc_ns_log.h"

LosTaskCB *kthread_run(int (*threadfn)(uintptr_t data, int data_len), void *data, int data_len, char *name)
{
	LosTaskCB *ktask = NULL;
	uint32_t task_id = 0;
	uint32_t ret;
	TSK_INIT_PARAM_S task_init_param;

	if (threadfn == NULL)
		return NULL;

	if (memset_s(&task_init_param, sizeof(TSK_INIT_PARAM_S), 0, sizeof(TSK_INIT_PARAM_S)) != EOK)
		return NULL;

	task_init_param.pfnTaskEntry = (TSK_ENTRY_FUNC)threadfn;
	task_init_param.uwStackSize  = LOSCFG_BASE_CORE_TSK_DEFAULT_STACK_SIZE;
	task_init_param.pcName	     = name;
	task_init_param.usTaskPrio   = 1;
	task_init_param.auwArgs[0]   = (uintptr_t)data;
	task_init_param.auwArgs[1]   = data_len;
	task_init_param.uwResved     = LOS_TASK_STATUS_DETACHED;

	ret = LOS_TaskCreate(&task_id, &task_init_param);
	if (ret != LOS_OK)
		return NULL;

	ktask = (LosTaskCB *)OS_TCB_FROM_TID(task_id);
	(void)LOS_TaskYield();
	return ktask;
}

void kthread_stop(const LosTaskCB *k)
{
	if (k != NULL)
		LOS_TaskDelete(k->taskID);
}

int kthread_should_stop(void)
{
	return (OsCurrTaskGet()->signal == SIGNAL_KILL);
}

ssize_t simple_read_from_buffer(void __user *to, size_t count,
				const void *from, size_t available)
{
	size_t ret;

	if (count == 0 || available == 0)
		return 0;

	if (count > available)
		count = available;

	ret = copy_to_user(to, from, count);
	if (ret == count)
		return -EFAULT;
	count -= ret;
	return count;
}

#define MAX_ORDER 31

LosVmPage *mailbox_pool_alloc_pages(unsigned int order)
{
	if (order > MAX_ORDER)
		return NULL;
	void *ptr = LOS_PhysPagesAllocContiguous(1UL << order);
	if (ptr == NULL) {
		PRINTK("mailbox pool contiguous ptr null size %x\n", 1 << order);
		return NULL;
	}
	for (int i = 0; i < (1UL << order); i++) {
		// mempool is used to mmap, add ref to prevent pmm free page to free list.
		LosVmPage *page = OsVmVaddrToPage((void *)((intptr_t)ptr + PAGE_SIZE * i));
		if (page != NULL)
			LOS_AtomicInc(&page->refCounts);
	}

	return OsVmVaddrToPage(ptr);
}

void mailbox_pool_free_pages(LosVmPage *page_array, size_t order)
{
	if (page_array == NULL || order > MAX_ORDER)
		return;

	for (int i = 0; i < (1UL << order); i++) {
		LOS_AtomicDec(&(page_array[i].refCounts));
		LOS_PhysPageFree(&page_array[i]);
	}
	LOS_PhysPagesFreeContiguous(page_array, (1UL << order));
}

int32_t do_vmalloc_remap(LosVmMapRegion *vma, void *kvaddr)
{
	int i;
	int ret = 0;
	paddr_t pa;
	uint32_t uflags = VM_MAP_REGION_FLAG_PERM_READ | VM_MAP_REGION_FLAG_PERM_WRITE | VM_MAP_REGION_FLAG_PERM_USER;
	LosVmPage *vm_page = NULL;

	if (vma == NULL || kvaddr == NULL)
		return -EINVAL;

	LosVmSpace *vm_space = LOS_SpaceGet(vma->range.base);
	if (vm_space == NULL)
		return -EINVAL;

	vaddr_t kva = (vaddr_t)(uintptr_t)kvaddr;
	vaddr_t uva = vma->range.base;
	unsigned int page;

	(void)LOS_MuxAcquire(&vm_space->regionMux);
	for (i = 0; i < (vma->range.size >> PAGE_SHIFT); i++) {
		page = (unsigned int)i;
		pa = LOS_PaddrQuery((void *)(uintptr_t)(kva + (page << PAGE_SHIFT)));
		if (pa == 0) {
			PRINT_ERR("%s, %d\n", __FUNCTION__, __LINE__);
			ret = -EINVAL;
			break;
		}
		vm_page = LOS_VmPageGet(pa);
		if (vm_page == NULL) {
			PRINT_ERR("%s, %d\n", __FUNCTION__, __LINE__);
			ret = -EINVAL;
			break;
		}
		status_t err = LOS_ArchMmuMap(&vm_space->archMmu, uva + (page << PAGE_SHIFT), pa, 1, uflags);
		if (err < 0) {
			ret = err;
			PRINT_ERR("%s, %d\n", __FUNCTION__, __LINE__);
			break;
		}
		LOS_AtomicInc(&vm_page->refCounts);
	}
	/* if any failure happened, rollback */
	if (i < (vma->range.size >> PAGE_SHIFT)) {
		for (i = i - 1; i >= 0; i--) {
			page = (unsigned int)i;
			pa = LOS_PaddrQuery((void *)(uintptr_t)(kva + (page << PAGE_SHIFT)));
			vm_page = LOS_VmPageGet(pa);
			(void)LOS_ArchMmuUnmap(&vm_space->archMmu, uva + (page << PAGE_SHIFT), 1);
			(void)LOS_PhysPageFree(vm_page);
		}
	}

	(void)LOS_MuxRelease(&vm_space->regionMux);
	return ret;
}

int remap_vmalloc_range(LosVmMapRegion *vma, void *addr, unsigned long pgoff)
{
	if (pgoff != 0)
		return -1;
	return do_vmalloc_remap(vma, addr);
}

int create_tc_client_device(const char *dev_name, const struct file_operations_vfs *op)
{
	int ret = register_driver(dev_name, op, TEE_DEV_PRI, NULL);
	if (unlikely(ret))
		return -1;

	return EOK;
}

int misc_register_adapt(struct miscdevice_adapt *misc_device)
{
	if (misc_device == NULL)
		return -1;

	int ret = register_driver(misc_device->name, misc_device->op, TEE_DEV_PRI, NULL);
	if (unlikely(ret))
		return -1;

	return EOK;
}

#define IV_LEN 16
#define KEY_BITS 256
#define MAX_AES_CRYPT_SIZE SZ_4M
int crypto_aescbckey256(unsigned char *output, const unsigned char *input, struct aes_param *param)
{
	mbedtls_aes_context ctx;
	int ret;
	if (!output || !input)
		return -1;

	if (!param || !param->iv || !param->key ||
		param->size < 0 ||  param->size > MAX_AES_CRYPT_SIZE)
		return -1;

	int mode = param->encrypto_type ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
	unsigned char iv_tmp[IV_LEN] = {0};

	ret = memcpy_s(iv_tmp, IV_LEN, param->iv, IV_LEN);
	if (ret != EOK)
		return -1;
	mbedtls_aes_init(&ctx);

	if (mode == MBEDTLS_AES_ENCRYPT)
		ret = mbedtls_aes_setkey_enc(&ctx, param->key, KEY_BITS);
	else
		ret = mbedtls_aes_setkey_dec(&ctx, param->key, KEY_BITS);
	if (ret)
		return -1;
	return mbedtls_aes_crypt_cbc(&ctx, mode, param->size, iv_tmp, input, output);
}

void set_vmm_region_code_start(uintptr_t code_start, uint32_t code_size)
{
	LosVmSpace *space = NULL;
	space = OsCurrProcessGet()->vmSpace;
	if (space->codeStart != 0)
		return;

	if (code_size == 0 || code_start + code_size < code_start)
		return;

	space->codeStart = code_start;
	space->codeEnd = code_start + code_size;
}

char *get_process_path(LosTaskCB *task, char *tpath, int path_len)
{
	if (task == NULL || tpath == NULL || path_len < 0 || path_len > MAX_PATH_SIZE)
		return NULL;

	struct Vnode *vnode = OS_PCB_FROM_PID(task->processID)->execVnode;
	if (vnode == NULL)
		return NULL;
	int ret = memset_s(tpath, path_len, '\0', path_len);
	if (ret != EOK) {
		tloge("memset error ret is %d\n", ret);
		return NULL;
	}

	ret = memcpy_s(tpath, path_len - 1, vnode->filePath, strlen(vnode->filePath));
	if (ret != EOK) {
		tloge("memcpy error ret is %d\n", ret);
		return NULL;
	}
	return tpath;
}

int calc_task_so_hash(unsigned char *digest, uint32_t dig_len,
	LosTaskCB *cur_struct, int so_index)
{
	tee_sha256_context ctx;
	bool find_flag = false;
	LosRbNode *rb_node = NULL;
	LosRbNode *rb_node_next = NULL;
	LosVmSpace *space = OS_PCB_FROM_PID(cur_struct->processID)->vmSpace;
	if (space == NULL)
		return -EFAULT;

	init_tee_sha256(&ctx);
	/* search the region list */
	(void)LOS_MuxAcquire(&space->regionMux);
	RB_SCAN_SAFE(&space->regionRbTree, rb_node, rb_node_next)
		LosVmMapRegion *region = (LosVmMapRegion *)rb_node;
		if (!LOS_IsRegionFileValid(region))
			continue;
		struct Vnode *vnode = region->unTypeData.rf.vnode;
		if (vnode != NULL && !strncmp(vnode->filePath, LIBTEEC_SO, strlen(LIBTEEC_SO))) {
			update_tee_sha256(&ctx, (void *)region->range.base, region->range.size);
			find_flag = true;
			break;
		}
	RB_SCAN_SAFE_END(&space->regionRbTree, rb_node, rb_node_next)
	(void)LOS_MuxRelease(&space->regionMux);

	if (!find_flag)
		return -EFAULT;
	finish_tee_sha256(&ctx, digest);
	return 0;
}
