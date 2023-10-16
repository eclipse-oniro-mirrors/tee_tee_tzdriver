/*
 * tc_ns_log.h
 *
 * log func declaration
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
#ifndef TC_NS_LOG_H
#define TC_NS_LOG_H

#include <linux/kernel.h>
enum {
	TZ_DEBUG_VERBOSE = 0,
	TZ_DEBUG_DEBUG,
	TZ_DEBUG_INFO,
	TZ_DEBUG_WARN,
	TZ_DEBUG_ERROR,
};
#define MOD_TEE "tzdriver"

#define TEE_USR_LOG_MASK 3
#define TEE_LOG_MASK TEE_USR_LOG_MASK

#define tlogv(fmt, args...) \
do { \
	if (TZ_DEBUG_VERBOSE >= TEE_LOG_MASK) \
		pr_info("([%s] %i, %s)%s: " fmt, MOD_TEE, OsCurrTaskGet()->taskID, OsCurrTaskGet()->taskName, __func__, ## args); \
} while (0)


#define tlogd(fmt, args...) \
do { \
	if (TZ_DEBUG_DEBUG >= TEE_LOG_MASK) \
		pr_info("([%s] %i, %s)%s: " fmt, MOD_TEE, OsCurrTaskGet()->taskID, OsCurrTaskGet()->taskName, __func__, ## args); \
} while (0)


#define tlogi(fmt, args...) \
do { \
	if (TZ_DEBUG_INFO >= TEE_LOG_MASK) \
		pr_info("([%s] %i, %s)%s: " fmt, MOD_TEE, OsCurrTaskGet()->taskID, OsCurrTaskGet()->taskName, __func__, ## args); \
} while (0)


#define tlogw(fmt, args...) \
do { \
	if (TZ_DEBUG_WARN >= TEE_LOG_MASK) \
		pr_warn("([%s] %i, %s)%s: " fmt, MOD_TEE, OsCurrTaskGet()->taskID, OsCurrTaskGet()->taskName, __func__, ## args); \
} while (0)


#define tloge(fmt, args...) \
		pr_err("([%s] %i, %s)%s: " fmt, MOD_TEE, OsCurrTaskGet()->taskID, OsCurrTaskGet()->taskName, __func__, ## args)

#endif
