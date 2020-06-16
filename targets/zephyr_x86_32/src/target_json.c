/*
 * Zephyr json fuzzing sample
 *
 * This file is in part based on Zephyr RTOS project
 * tests/lib/json/src/main.c
 *
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <kernel.h>
#include <data/json.h>

#include <string.h>
#include <sys/types.h>

/*
 * Structs and description are part of Zephyr's test
 */
struct test_nested {
	int nested_int;
	bool nested_bool;
	const char *nested_string;
};

struct test_struct {
	const char *some_string;
	int some_int;
	bool some_bool;
	struct test_nested some_nested_struct;
	int some_array[16];
	size_t some_array_len;
	bool another_bxxl;               /* JSON field: "another_b!@l" */
	bool if_;                        /* JSON: "if" */
	int another_array[10];           /* JSON: "another-array" */
	size_t another_array_len;
	struct test_nested xnother_nexx; /* JSON: "4nother_ne$+" */
};

static const struct json_obj_descr nested_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct test_nested, nested_int, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct test_nested, nested_bool, JSON_TOK_TRUE),
	JSON_OBJ_DESCR_PRIM(struct test_nested, nested_string,
			JSON_TOK_STRING),
};

static const struct json_obj_descr description[] = {
	JSON_OBJ_DESCR_PRIM(struct test_struct, some_string, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct test_struct, some_int, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct test_struct, some_bool, JSON_TOK_TRUE),
	JSON_OBJ_DESCR_OBJECT(struct test_struct, some_nested_struct,
			nested_descr),
	JSON_OBJ_DESCR_ARRAY(struct test_struct, some_array,
			16, some_array_len, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM_NAMED(struct test_struct, "another_b!@l",
			another_bxxl, JSON_TOK_TRUE),
	JSON_OBJ_DESCR_PRIM_NAMED(struct test_struct, "if",
			if_, JSON_TOK_TRUE),
	JSON_OBJ_DESCR_ARRAY_NAMED(struct test_struct, "another-array",
			another_array, 10, another_array_len,
			JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_OBJECT_NAMED(struct test_struct, "4nother_ne$+",
			xnother_nexx, nested_descr),
};

void target_init() {};

ssize_t target_entry(const char *buf, size_t len)
{
	int ret;
	struct test_struct desc;

	ret = json_obj_parse((char *)buf, len, description,
			ARRAY_SIZE(description), &desc);

	return (ssize_t)ret;
}

