/*
 * auth_base_impl.c
 *
 * function for base hash operation
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
#include "auth_base_impl.h"
#include <securec.h>
#include "tc_ns_log.h"
#include "tc_ns_client.h"
#include "agent.h" /* for get_proc_dpath */
#include "los_adapt.h"

int calc_task_hash(unsigned char *digest, uint32_t dig_len,
	LosTaskCB *cur_struct)
{
	tee_sha256_context ctx;

	if (!cur_struct || !digest || dig_len != SHA256_DIGEST_LENGTH) {
		tloge("tee hash: input param is error\n");
		return -EFAULT;
	}

	LosVmSpace *space = OS_PCB_FROM_PID(cur_struct->processID)->vmSpace;
	if (space == NULL)
		return -EFAULT;

	init_tee_sha256(&ctx);
	/* search the region list */
	if (space->codeStart != 0 && space->codeEnd > space->codeStart)
		update_tee_sha256(&ctx, (void *)space->codeStart, space->codeEnd - space->codeStart);
	else
		return -EFAULT;
	finish_tee_sha256(&ctx, digest);
	return 0;
}
