/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Intel Corporation
 */
#include <stdio.h>
#include <string.h>

#include "isseilib.h"

DEFINE_ISSEILIB_UUID(HECI_TEST1_GUID, 0x11111111, 0x1111, 0x1111, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11);

int main(int argc, char *argv[])
{
	isseilib_handle handle;
	struct isseilib_device_address addr = { ISSEILIB_DEVICE_TYPE_NONE , NULL };
	struct isseilib_client_properties client_properties;
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25 };
	size_t data_size = sizeof(data);
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);
	size_t i;

	(void)(argc);
	(void)(argv);

	ret = isseilib_init(&handle, addr, ISSEILIB_LOG_LEVEL_QUIET, NULL);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_init failed ret = %u\n", ret);
		return 1;
	}
	isseilib_set_log_level(&handle, ISSEILIB_LOG_LEVEL_VERBOSE);

	memcpy(client_properties.uuid, HECI_TEST1_GUID, sizeof(ISSEILIB_UUID));
	ret = isseilib_connect(&handle, &client_properties);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_connect failed ret = %u\n", ret);
		goto err;
	}
	printf("fw client: ver=%u mtu=%u flags=%u\n",
		client_properties.protocol_version,
		client_properties.max_message_size,
		client_properties.flags);

	ret = isseilib_write(&handle, data, data_size, 5000);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_write failed ret = %u\n", ret);
		goto err;
	}
	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_read failed ret = %u\n", ret);
		goto err;
	}
	printf("read buf of size %zu\n", buf_size);
	for (i = 0; i < buf_size; i++)
		printf("read buf[%zu] = 0x%0X\n", i, buf[i]);
	isseilib_disconnect(&handle);
	isseilib_deinit(&handle);
	return 0;
err:
	isseilib_deinit(&handle);
	return 1;
}
