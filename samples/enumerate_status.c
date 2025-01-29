/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2024 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isseilib.h"

void print_uuid(const ISSEILIB_UUID uuid)
{
		printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

DEFINE_ISSEILIB_UUID(HECI_TEST4_GUID, 0x44444444, 0x4444, 0x4444, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44);
DEFINE_ISSEILIB_UUID(HECI_TEST0_GUID, 0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

int main(int argc, char *argv[])
{
	isseilib_handle handle;
	uint32_t driver_status = 0;
	struct isseilib_device_address addr = { ISSEILIB_DEVICE_TYPE_NONE , NULL };
	struct isseilib_device_fw_version fw_version = { 0 };
	uint32_t fw_status = 0;
	struct isseilib_client_properties* client_properties;
	size_t num_clients = 0;
	bool exists;
#define KIND_SIZE 128
	char kind[KIND_SIZE];
	size_t kind_size = KIND_SIZE;
	uint32_t ret;
	size_t i;

	(void)(argc);
	(void)(argv);
	
	ret = isseilib_init(&handle, addr, ISSEILIB_LOG_LEVEL_ERROR, NULL);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_init failed ret = %u\n", ret);
		return 1;
	}
#ifdef DEBUG
	isseilib_set_log_level(&handle, ISSEILIB_LOG_LEVEL_VERBOSE);
#endif /* DEBUG */
	ret = isseilib_get_status(&handle, &driver_status);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_get_status failed ret = %u\n", ret);
	} else {
		printf("isseilib_get_status succeed status = 0x%x\n", driver_status);
	}

	ret = isseilib_get_kind(&handle, kind, &kind_size);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_get_kind failed ret = %u\n", ret);
	} else {
		printf("isseilib_get_kind succeed kind = '%s' size = %zu\n", kind, kind_size);
	}

	ret = isseilib_get_fw_version(&handle, &fw_version);
	if (ret != ISSEILIB_SUCCESS) {
		printf("isseilib_get_fw_version failed ret = %u\n", ret);
	}else {
		printf("isseilib_get_fw_version succeed version {%d.%d.%d.%d}\n",
			fw_version.major, fw_version.minor, fw_version.hotfix, fw_version.build);
	}

	for (uint8_t sts = 0; sts < 6; sts++)
	{
		ret = isseilib_get_fw_status(&handle, sts, &fw_status);
		if (ret != ISSEILIB_SUCCESS) {
			printf("isseilib_get_fw_status %d failed ret = %u\n", sts, ret);
		}
		else {
			printf("isseilib_get_fw_status %d succeed status = 0x%x\n",
			       sts, fw_status);
		}
	}

	ret = isseilib_get_client_list(&handle, NULL, &num_clients);
	if (ret != ISSEILIB_SUCCESS && ret != ISSEILIB_ERROR_SMALL_BUFFER) {
		printf("isseilib_get_client_list failed ret = %u\n", ret);
		goto err;
	}
	printf("isseilib_get_client_list returned %zu clients\n", num_clients);
	client_properties = calloc(num_clients, sizeof(struct isseilib_client_properties));
	if (!client_properties) {
		printf("calloc client_properties failed\n");
	} else {
		ret = isseilib_get_client_list(&handle, client_properties, &num_clients);
		if (ret != ISSEILIB_SUCCESS) {
			printf("isseilib_get_client_list failed ret = %u\n", ret);
		} else {
			for (i = 0; i < num_clients; i++) {
				print_uuid(client_properties[i].uuid);
				printf(" ver=%u mtu=%u flags=%u\n", client_properties[i].protocol_version,
				       client_properties[i].max_message_size, client_properties[i].flags);
			}
		}
	}
	free(client_properties);

	exists = false;
	ret = isseilib_is_client_exists(&handle, HECI_TEST4_GUID, &exists);
	if (ret != ISSEILIB_SUCCESS)
	{
		printf("isseilib_is_client_exists for TEST4 failed ret = %u\n", ret);
	}
	else
	{
		printf("isseilib_is_client_exists for TEST4 succeeded exists = %d\n", exists);
	}
	exists = false;
	ret = isseilib_is_client_exists(&handle, HECI_TEST0_GUID, &exists);
	if (ret != ISSEILIB_SUCCESS)
	{
		printf("isseilib_is_client_exists for TEST0 failed ret = %u\n", ret);
	}
	else
	{
		printf("isseilib_is_client_exists for TEST0 succeeded exists = %d\n", exists);
	}
err:
	isseilib_deinit(&handle);
	return 0;
}
