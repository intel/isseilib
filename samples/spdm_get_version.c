/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * SPDM standard: https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.1.pdf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isseilib.h"

DEFINE_ISSEILIB_UUID(HECI_SPDM_GUID,
	0xe85149df, 0x9447, 0x4C9A, 0x83, 0x67, 0xC4, 0xE3, 0x34, 0x64, 0xF1, 0xB4);

#define SPDM_MESSAGE_VERSION_10 0x10
#define SPDM_GET_VERSION_REQ 0x84
#define SPDM_GET_VERSION_RSP 0x04

#pragma pack(1)
struct spdm_command_header {
	uint8_t ver;
	uint8_t cmd;
	uint8_t param1;
	uint8_t param2;
};

struct spdm_get_version_req {
	struct spdm_command_header hdr;
};

#pragma warning(disable : 4200)
struct spdm_get_version_rsp {
	struct spdm_command_header hdr;
	uint8_t reserved;
	uint8_t count;
	uint16_t versions[];
};
#pragma pack()

int main(int argc, char *argv[])
{
	isseilib_handle handle;
	struct isseilib_device_address addr = { ISSEILIB_DEVICE_TYPE_NONE , NULL };
	struct isseilib_client_properties client_properties;
	const struct spdm_get_version_req req =
       		{ SPDM_MESSAGE_VERSION_10, SPDM_GET_VERSION_REQ, 0, 0};
	uint8_t *buf = NULL;
	struct spdm_get_version_rsp *rsp;
	size_t buf_size;
	size_t i;
	uint32_t ret;

	(void)(argc);
	(void)(argv);

	ret = isseilib_init(&handle, addr, ISSEILIB_LOG_LEVEL_ERROR, NULL);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_init failed ret = %u\n", ret);
		return 1;
	}

	memcpy(client_properties.uuid, HECI_SPDM_GUID, sizeof(ISSEILIB_UUID));
	ret = isseilib_connect(&handle, &client_properties);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_connect failed ret = %u\n", ret);
		goto err;
	}

	buf_size = client_properties.max_message_size;
	buf = malloc(buf_size);
	if (buf == NULL) {
		printf("failed to allocate buffer of %zu bytes\n", buf_size);
		goto err;
	}

	ret = isseilib_write(&handle, (const uint8_t *)&req, sizeof(req), 5000);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_write failed ret = %u\n", ret);
		goto err;
	}
	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_read failed ret = %u\n", ret);
		goto err;
	}
	if (buf_size < sizeof(*rsp)) {
		printf("response is too small %zu < %zu\n", buf_size, sizeof(*rsp));
		goto err;
	}
	rsp = (struct spdm_get_version_rsp *)buf;
	if (rsp->hdr.ver != SPDM_MESSAGE_VERSION_10 || rsp->hdr.cmd != SPDM_GET_VERSION_RSP) {
		printf("wrong response\n");
		goto err;
	}
	if (rsp->count * sizeof(uint16_t) > buf_size - sizeof(*rsp)) {
		printf("response is truncated\n");
		goto err;
	}
	for (i = 0; i < rsp->count; i++)
		printf("version[%zu] = 0x%0X\n", i, rsp->versions[i]);
	isseilib_disconnect(&handle);
	isseilib_deinit(&handle);
	return 0;
err:
	isseilib_deinit(&handle);
	if (buf)
		free(buf);
	return 1;
}
