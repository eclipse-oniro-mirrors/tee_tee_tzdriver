/*
 * teek_client_ext.c
 *
 * exported funcs for teek client ext
 *
 * Copyright (c) 2012-2022 Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "teek_client_ext.h"
#include "smc_smp.h"
#include "mailbox_mempool.h"
#include "teek_client_constants.h"
#include "tz_update_crl.h"
#include "internal_functions.h"
#include "tc_client_driver.h"

#ifdef CONFIG_CMS_SIGNATURE
/* update crl */
uint32_t teek_update_crl(uint8_t *crl, uint32_t crl_len)
{
	if (!get_tz_init_flag()) return EFAULT;
	if (crl == NULL || crl_len == 0 || crl_len > DEVICE_CRL_MAX) {
		tloge("bad params\n");
		return -EINVAL;
	}

	livepatch_down_read_sem();
	int ret = send_crl_to_tee(crl, crl_len, NULL);
	livepatch_up_read_sem();
	if (ret != 0)
		tloge("update crl failed, ret %d\n", ret);

	return ret;
}
EXPORT_SYMBOL(teek_update_crl);
#endif