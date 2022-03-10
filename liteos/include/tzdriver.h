/*
 * tzdriver.h
 *
 * functions for tzdriver
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

#ifndef TZDRIVER_H
#define TZDRIVER_H

int tc_init(void);
void set_vmm_region_code_start(uintptr_t code_start, uint32_t code_size);

#endif
