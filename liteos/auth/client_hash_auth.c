/*
 * client_hash_auth.c
 *
 * function for CA code hash auth
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
#include "client_hash_auth.h"
#include <securec.h>
#include "tc_ns_log.h"
#include "auth_base_impl.h"
#include "los_adapt.h"

static int proc_calc_hash(uint8_t kernel_api, struct tc_ns_session *session,
	LosTaskCB *cur_struct)
{
	int rc, i;
	int so_found = 0;

	if (kernel_api == TEE_REQ_FROM_USER_MODE) {
		for (i = 0; so_found < NUM_OF_SO && i < KIND_OF_SO; i++) {
			rc = calc_task_so_hash(session->auth_hash_buf + MAX_SHA_256_SZ * so_found,
				(uint32_t)SHA256_DIGEST_LENGTH, cur_struct, i);
			if (!rc)
				so_found++;
		}
		if (so_found != NUM_OF_SO)
			tlogd("so library found: %d\n", so_found);
	} else {
		tlogd("request from kernel\n");
	}

#ifdef CONFIG_ASAN_DEBUG
	tloge("so auth disabled for ASAN debug\n");
	uint32_t so_hash_len = MAX_SHA_256_SZ * NUM_OF_SO;
	errno_t sret = memset_s(session->auth_hash_buf, so_hash_len, 0, so_hash_len);
	if (sret) {
		tloge("memset so hash failed\n");
		return -EFAULT;
	}
#endif

	rc = calc_task_hash(session->auth_hash_buf + MAX_SHA_256_SZ * NUM_OF_SO,
		(uint32_t)SHA256_DIGEST_LENGTH, cur_struct);
	if (rc) {
		tloge("tee calc ca hash failed\n");
		return -EFAULT;
	}
	return EOK;
}

int calc_client_auth_hash(struct tc_ns_dev_file *dev_file,
	struct tc_ns_client_context *context, struct tc_ns_session *session)
{
	int ret;
	LosTaskCB *cur_struct = NULL;
	bool check = false;

	check = (!dev_file || !context || !session);
	if (check) {
		tloge("bad params\n");
		return -EFAULT;
	}

	cur_struct = OsCurrTaskGet();

	ret = proc_calc_hash(dev_file->kernel_api, session, cur_struct);
	return ret;
}
