/*
 * ko_adapt.c
 *
 * function for find symbols not exported
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
#include "ko_adapt.h"
#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/stddef.h>
#include <linux/cred.h>
#include <linux/version.h>
#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/task.h>
#endif
#include <linux/cpumask.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include "tc_ns_log.h"

typedef const struct cred *(get_task_cred_func)(struct task_struct *);
typedef void (kthread_bind_mask_func)(struct task_struct *, const struct cpumask *);
typedef long (sys_chown_func)(const char __user *filename,
		uid_t user, gid_t group);
typedef ssize_t (vfs_write_func)(struct file *file, const char __user *buf,
		size_t count, loff_t *pos);
typedef ssize_t (vfs_read_func)(struct file *file, char __user *buf,
		size_t count, loff_t *pos);

typedef struct page *(alloc_pages_func)(gfp_t gfp_mask, unsigned int order);

typedef struct workqueue_attrs *(alloc_workqueue_attrs_func)(gfp_t gfp_mask);
typedef void (free_workqueue_attrs_func)(struct workqueue_attrs *attrs);

const struct cred *koadpt_get_task_cred(struct task_struct *task)
{
	static get_task_cred_func *get_task_cred_pt = NULL;

	if (!task)
		return NULL;

	if (!get_task_cred_pt) {
		get_task_cred_pt = (get_task_cred_func *)
			(uintptr_t)kallsyms_lookup_name("get_task_cred");
		if (IS_ERR_OR_NULL(get_task_cred_pt)) {
			tloge("fail to find symbol get task cred\n");
			return NULL;
		}
	}
	return get_task_cred_pt(task);
}

void koadpt_kthread_bind_mask(struct task_struct *task,
	const struct cpumask *mask)
{
	static kthread_bind_mask_func *kthread_bind_mask_pt = NULL;

	if (!task || !mask)
		return;

	if (!kthread_bind_mask_pt) {
		kthread_bind_mask_pt = (kthread_bind_mask_func *)
			(uintptr_t)kallsyms_lookup_name("kthread_bind_mask");
		if (IS_ERR_OR_NULL(kthread_bind_mask_pt)) {
			tloge("fail to find symbol kthread bind mask\n");
			return;
		}
	}
	kthread_bind_mask_pt(task, mask);
}

long koadpt_sys_chown(const char __user *filename, uid_t user, gid_t group)
{
	static sys_chown_func *sys_chown_pt = NULL;

	if (!filename)
		return -EINVAL;

	if (!sys_chown_pt) {
		sys_chown_pt = (sys_chown_func *)
			(uintptr_t)kallsyms_lookup_name("sys_chown");
		if (IS_ERR_OR_NULL(sys_chown_pt)) {
			tloge("fail to find symbol kthread bind mask\n");
			return -EINVAL;
		}
	}
	return sys_chown_pt(filename, user, group);
}

ssize_t koadpt_vfs_write(struct file *file, const char __user *buf,
	size_t count, loff_t *pos)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 116))
	static vfs_write_func *vfs_write_pt = NULL;

	if (!file || !buf || !pos)
		return -EINVAL;

	if (!vfs_write_pt) {
		vfs_write_pt = (vfs_write_func *)
			(uintptr_t)kallsyms_lookup_name("vfs_write");
		if (IS_ERR_OR_NULL(vfs_write_pt)) {
			tloge("fail to find symbol vfs write\n");
			return -EINVAL;
		}
	}
	return vfs_write_pt(file, buf, count, pos);
#else
	return vfs_write(file, buf, count, pos);
#endif
}

ssize_t koadpt_vfs_read(struct file *file, char __user *buf,
	size_t count, loff_t *pos)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 116))
	static vfs_read_func *vfs_read_pt = NULL;

	if (!file || !buf || !pos)
		return -EINVAL;

	if (!vfs_read_pt) {
		vfs_read_pt = (vfs_read_func *)
			(uintptr_t)kallsyms_lookup_name("vfs_read");
		if (IS_ERR_OR_NULL(vfs_read_pt)) {
			tloge("fail to find symbol vfs read\n");
			return -EINVAL;
		}
	}
	return vfs_read_pt(file, buf, count, pos);
#else
	return vfs_read(file, buf, count, pos);
#endif
}

struct page *koadpt_alloc_pages(gfp_t gfp_mask, unsigned int order)
{
#ifdef CONFIG_NUMA
	static alloc_pages_func *alloc_pages_pt = NULL;

	if (!alloc_pages_pt) {
		alloc_pages_pt = (alloc_pages_func *)
			(uintptr_t)kallsyms_lookup_name("alloc_pages_current");
		if (IS_ERR_OR_NULL(alloc_pages_pt)) {
			tloge("fail to find symbol alloc pages current\n");
			return NULL;
		}
	}
	return alloc_pages_pt(gfp_mask, order);
#else
	return alloc_pages(gfp_mask, order);
#endif
}

struct workqueue_attrs *koadpt_alloc_workqueue_attrs(gfp_t gfp_mask)
{
	static alloc_workqueue_attrs_func *alloc_workqueue_attrs_pt = NULL;

	if (!alloc_workqueue_attrs_pt) {
		alloc_workqueue_attrs_pt = (alloc_workqueue_attrs_func *)
			(uintptr_t)kallsyms_lookup_name("alloc_workqueue_attrs");
		if (IS_ERR_OR_NULL(alloc_workqueue_attrs_pt)) {
			tloge("fail to find symbol alloc workqueue attrs\n");
			return NULL;
		}
	}
	return alloc_workqueue_attrs_pt(gfp_mask);
}

void koadpt_free_workqueue_attrs(struct workqueue_attrs *attrs)
{
	static free_workqueue_attrs_func *free_workqueue_attrs_pt = NULL;

	if (!attrs)
		return;

	if (!free_workqueue_attrs_pt) {
		free_workqueue_attrs_pt = (free_workqueue_attrs_func *)
			(uintptr_t)kallsyms_lookup_name("free_workqueue_attrs");
		if (IS_ERR_OR_NULL(free_workqueue_attrs_pt)) {
			tloge("fail to find symbol free workqueue attrs\n");
			return;
		}
	}
	free_workqueue_attrs_pt(attrs);
}
