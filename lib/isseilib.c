/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2024 Intel Corporation
 */
/*! \file isseilib.c
 *  \brief issei access library API
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isseilib.h"
#include "internal.h"

void __issei_deinit_handle(IN OUT struct issei_int_handle *int_handle)
{
	if (int_handle->device_path)
		free(int_handle->device_path);
	free(int_handle);
}

ISSEILIB_DLL_API uint32_t isseilib_init(IN OUT isseilib_handle *handle,
	IN const struct isseilib_device_address device,
	IN uint32_t log_level, IN OPTIONAL isseilib_log_callback log_callback)
{
	struct issei_int_handle* int_handle;
	uint32_t ret;

	if (!handle)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	*handle = NULL;

	int_handle = calloc(1, sizeof(*int_handle));
	if (!int_handle)
	{
		return ISSEILIB_ERROR_GENERAL;
	}
	int_handle->handle = ISSEILIB_INVALID_DEVICE_HANDLE;
	int_handle->state = ISSEI_CLIENT_STATE_NONE;
	int_handle->log_level = (log_level >= ISSEILIB_LOG_LEVEL_MAX) ? ISSEILIB_LOG_LEVEL_VERBOSE : log_level;
	int_handle->log_callback = log_callback;

	FUNC_ENTRY(int_handle);

	if (log_level >= ISSEILIB_LOG_LEVEL_MAX) {
		ERRPRINT(int_handle, "LogLevel %u is too big.\n", log_level);
		ret = ISSEILIB_ERROR_INVALID_PARAM;
		goto Cleanup;
	}

	switch (device.type) {
	case ISSEILIB_DEVICE_TYPE_NONE:
		if (device.data.path != NULL) {
			ERRPRINT(int_handle, "Path is not NULL.\n");
			ret = ISSEILIB_ERROR_INVALID_PARAM;
			goto Cleanup;
		}
		ret = __issei_init_internal_null(int_handle);
		if (ret != ISSEILIB_SUCCESS)
		{
			goto Cleanup;
		}
		int_handle->close_on_exit = true;
		break;
	case ISSEILIB_DEVICE_TYPE_PATH:
		if (device.data.path == NULL) {
			ERRPRINT(int_handle, "Path is NULL.\n");
			ret = ISSEILIB_ERROR_INVALID_PARAM;
			goto Cleanup;
		}
		ret = __issei_init_internal_path(int_handle, device.data.path);
		if (ret != ISSEILIB_SUCCESS)
		{
			goto Cleanup;
		}
		int_handle->close_on_exit = true;
		break;
	case ISSEILIB_DEVICE_TYPE_HANDLE:
		if (device.data.handle == ISSEILIB_INVALID_DEVICE_HANDLE) {
			ERRPRINT(int_handle, "Handle is invalid.\n");
			ret = ISSEILIB_ERROR_INVALID_PARAM;
			goto Cleanup;
		}
		ret = __issei_init_internal_handle(int_handle, device.data.handle);
		if (ret != ISSEILIB_SUCCESS)
		{
			goto Cleanup;
		}
		int_handle->close_on_exit = false;
		break;
	default:
		ERRPRINT(int_handle, "Wrong device type %u.\n", device.type);
		ret = ISSEILIB_ERROR_INVALID_PARAM;
		goto Cleanup;
		break;
	}

	*handle = int_handle;
	ret = ISSEILIB_SUCCESS;
Cleanup:
	FUNC_EXIT(int_handle, ret);
	if (ret != ISSEILIB_SUCCESS)
	{
		__issei_deinit_handle(int_handle);
	}
	return ret;
}

ISSEILIB_DLL_API void isseilib_deinit(IN isseilib_handle *handle)
{
	struct issei_int_handle *int_handle;

	if (!handle || !*handle)
	{
		return;
	}

	int_handle = *handle;

	isseilib_disconnect(handle);

	__issei_deinit_internal(int_handle);
	__issei_deinit_handle(int_handle);
	*handle = NULL;
}

ISSEILIB_DLL_API uint32_t isseilib_connect(IN isseilib_handle *handle, IN OUT struct isseilib_client_properties *client_properties)
{
	struct issei_int_handle *int_handle;
	uint32_t status;

	if (!handle || !*handle || !client_properties)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;
	
	FUNC_ENTRY(int_handle);

	if (int_handle->state == ISSEI_CLIENT_STATE_CONNECTED)
	{
		status = ISSEILIB_ERROR_BUSY;
		ERRPRINT(int_handle, "The client is already connected\n");
		goto Cleanup;
	}

	if (int_handle->state == ISSEI_CLIENT_STATE_FAILED && int_handle->close_on_exit)
	{

		/* the handle have to be reopened in this case to reconnect to work */
		status = __issei_reopen(int_handle);
		if (status != ISSEILIB_SUCCESS)
		{
			goto Cleanup;
		}
	}

	COPY_UUID(int_handle->properties.uuid, client_properties->uuid);
	status = __issei_connect_ioctl(int_handle);
	if (status)
	{
		goto Cleanup;
	}
	int_handle->state = ISSEI_CLIENT_STATE_CONNECTED;

	client_properties->max_message_size = int_handle->properties.max_message_size;
	client_properties->protocol_version = int_handle->properties.protocol_version;
	client_properties->flags = int_handle->properties.flags;

Cleanup:

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_disconnect(IN isseilib_handle *handle)
{
	struct issei_int_handle *int_handle;
	uint32_t status;

	if (!handle || !*handle)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	if (int_handle->state != ISSEI_CLIENT_STATE_CONNECTED) {
		status = ISSEILIB_SUCCESS;
		DBGPRINT(int_handle, "The client is already disconnected\n");
		goto Cleanup;
	}
	status = __issei_disconnect_ioctl(int_handle);
	if (status)
	{
		goto Cleanup;
	}
	int_handle->state = ISSEI_CLIENT_STATE_NONE;

Cleanup:

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_write(IN isseilib_handle *handle, IN const uint8_t *data, IN size_t data_size, IN OPTIONAL uint32_t timeout)
{
	struct issei_int_handle *int_handle;
	uint32_t status;

	if (!handle || !*handle)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}
	
	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	if (!data || !data_size)
	{
		status = ISSEILIB_ERROR_INVALID_PARAM;
		ERRPRINT(int_handle, "One of the parameters was illegal\n");
		goto Cleanup;
	}

	if (data_size > int_handle->properties.max_message_size)
	{
		status = ISSEILIB_ERROR_INVALID_PARAM;
		ERRPRINT(int_handle, "Data size %zu bigger than MTU %u\n",
			 data_size, int_handle->properties.max_message_size);
		goto Cleanup;
	}

	if (int_handle->state != ISSEI_CLIENT_STATE_CONNECTED)
	{
		status = ISSEILIB_ERROR_DISCONNECTED;
		ERRPRINT(int_handle, "The client is not connected\n");
		goto Cleanup;
	}

	status = __issei_write_internal(int_handle, data, data_size, timeout);
	if (status)
	{
		if (status != ISSEILIB_ERROR_TIMEOUT)
		{
			int_handle->state = ISSEI_CLIENT_STATE_FAILED;
		}
		goto Cleanup;
	}

Cleanup:
	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_read(IN isseilib_handle *handle, uint8_t* data, IN OUT size_t *data_size, IN OPTIONAL uint32_t timeout)
{
	struct issei_int_handle *int_handle;
	uint32_t status;

	if (!handle || !*handle)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	if (!data || !data_size || !*data_size)
	{
		status = ISSEILIB_ERROR_INVALID_PARAM;
		ERRPRINT(int_handle, "One of the parameters was illegal\n");
		goto Cleanup;
	}

	if (int_handle->state != ISSEI_CLIENT_STATE_CONNECTED)
	{
		status = ISSEILIB_ERROR_DISCONNECTED;
		ERRPRINT(int_handle, "The client is not connected\n");
		goto Cleanup;
	}

	status = __issei_read_internal(int_handle, data, data_size, timeout);
	if (status)
	{
		if (status != ISSEILIB_ERROR_TIMEOUT)
		{
			int_handle->state = ISSEI_CLIENT_STATE_FAILED;
		}
		goto Cleanup;
	}

Cleanup:
	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_get_status(IN isseilib_handle *handle, OUT uint32_t *driver_status)
{
	struct issei_int_handle *int_handle;
	uint32_t status;

	if (!handle || !*handle || !driver_status)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	status = __issei_driver_status_ioctl(int_handle, driver_status);

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_get_kind(IN isseilib_handle *handle,
					    OUT char *kind, IN OUT size_t *kind_size)
{
	struct issei_int_handle *int_handle;
	uint32_t status;

	if (!handle || !*handle || !kind_size || !*kind_size)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	status = __issei_get_kind(int_handle, kind, kind_size);

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_set_log_level(IN isseilib_handle *handle, IN uint32_t log_level)
{
	struct issei_int_handle *int_handle;
	uint32_t status = ISSEILIB_SUCCESS;

	if (!handle || !*handle || log_level > ISSEILIB_LOG_LEVEL_VERBOSE)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	int_handle->log_level = log_level;

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_get_log_level(IN isseilib_handle *handle, OUT uint32_t *log_level)
{
	struct issei_int_handle *int_handle;
	uint32_t status = ISSEILIB_SUCCESS;

	if (!handle || !*handle || !log_level)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	*log_level = int_handle->log_level;

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_get_fw_version(IN isseilib_handle *handle,
						  OUT struct isseilib_device_fw_version *fw_version)
{
	struct issei_int_handle* int_handle;
	uint32_t status = ISSEILIB_SUCCESS;

	if (!handle || !*handle || !fw_version)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	status = __isseilib_get_fw_version(int_handle, fw_version);

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_get_fw_status(IN isseilib_handle *handle,
						 IN uint8_t register_number, OUT uint32_t *fw_status)
{
	struct issei_int_handle* int_handle;
	uint32_t status;

	if (!handle || !*handle || !fw_status || register_number > ISSEI_MAX_FW_STATUS)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	status = __isseilib_get_fw_status(int_handle, register_number, fw_status);

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_get_client_list(IN isseilib_handle *handle,
						   OUT struct isseilib_client_properties *client_properties,
						   IN OUT size_t *num_clients)
{
	struct issei_int_handle* int_handle;
	uint32_t status;

	if (!handle || !num_clients)
		return ISSEILIB_ERROR_INVALID_PARAM;

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	status = __isseilib_get_client_list(int_handle, client_properties, num_clients);

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_is_client_exists(IN isseilib_handle *handle,
						    IN const ISSEILIB_UUID client_uuid, OUT bool *exists)
{
	struct issei_int_handle* int_handle;
	uint32_t status;

	if (!handle || !*handle || !client_uuid)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	status = __isseilib_is_client_exists(int_handle, client_uuid, exists);

	FUNC_EXIT(int_handle, status);

	return status;
}

ISSEILIB_DLL_API uint32_t isseilib_set_log_callback(IN isseilib_handle* handle, isseilib_log_callback log_callback)
{
	struct issei_int_handle* int_handle;
	uint32_t status;

	if (!handle || !*handle)
	{
		return ISSEILIB_ERROR_INVALID_PARAM;
	}

	int_handle = *handle;

	FUNC_ENTRY(int_handle);

	int_handle->log_callback = log_callback;
	status = ISSEILIB_SUCCESS;

	FUNC_EXIT(int_handle, status);
	return status;
}

#define ISSEILIB_UUID_SIZE 36
int uuid_map[ISSEILIB_UUID_SIZE] =
{
	0,0,
	1,1,
	2,2,
	3,3,
	-1,
	4,4,
	5,5,
	-1,
	6,6,
	7,7,
	-1,
	8,8,
	9,9,
	-1,
	10,10,
	11,11,
	12,12,
	13,13,
	14,14,
	15,15
};

int PARSE_UUID(const char* src, ISSEILIB_UUID dst)
{
	char buf[3] = "00";
	bool tik = false;
	size_t i;

	for (i = 0; i < 36; i++)
	{
		if (src[i] == '\0')
			return -1;
		if ((i == 8) || (i == 13) || (i == 18) || (i == 23))
		{
			if (src[i] != '-')
				return -1;
			if (tik)
				return -1;
			continue;
		}
		if (!isxdigit(src[i]))
			return -1;
		if (tik)
		{
			buf[0] = src[i - 1];
			buf[1] = src[i];
			dst[uuid_map[i]] = (unsigned char)strtoul(buf, NULL, 16);
			tik = false;
		}
		else
		{
			tik = true;
		}
	}
	return 0;
}

int PARSE_UUIDW(const wchar_t* src, ISSEILIB_UUID dst)
{
	char buf[3] = "00";
	bool tik = false;
	size_t i;

	for (i = 0; i < 36; i++)
	{
		if (src[i] == '\0')
			return -1;
		if ((i == 8) || (i == 13) || (i == 18) || (i == 23))
		{
			if(src[i] != '-')
				return -1;
			if (tik)
				return -1;
			continue;
		}
		if (src[i] > 255)
			return -1;
		if (!isxdigit(src[i]))
			return -1;
		if (tik)
		{
			buf[0] = (char)src[i - 1];
			buf[1] = (char)src[i];
			dst[uuid_map[i]] = (unsigned char)strtoul(buf, NULL, 16);
			tik = false;
		}
		else
		{
			tik = true;
		}
	}
	return 0;
}

int PRINT_UUID(const ISSEILIB_UUID src, char* dst, size_t dst_size)
{
	return snprintf(dst, dst_size,
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
		src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15]);
}
