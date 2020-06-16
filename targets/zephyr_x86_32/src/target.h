/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _KAFL_VULN_TEST_H_
#define _KAFL_VULN_TEST_H_

#include <sys/types.h>

void target_init();

ssize_t target_entry(const char *buf, size_t len);


#endif /* _KAFL_VULN_TEST_H_ */
