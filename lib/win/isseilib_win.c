/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2024 Intel Corporation
 */
#include <windows.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <stdarg.h>

#include "isseilib.h"
#include "internal.h"
#include "public.h"

/* Windows helpers */

static uint32_t err_win32_to_issei(_In_ DWORD err)
{
	switch (err) {
	case ERROR_INVALID_HANDLE:
		return ISSEILIB_ERROR_INVALID_PARAM;
	case ERROR_INSUFFICIENT_BUFFER:
		return ISSEILIB_ERROR_SMALL_BUFFER;
	case ERROR_INVALID_USER_BUFFER:
		return ISSEILIB_ERROR_SMALL_BUFFER;
	case ERROR_GEN_FAILURE:
		return ISSEILIB_ERROR_GENERAL;
	case ERROR_DEVICE_NOT_CONNECTED:
		return ISSEILIB_ERROR_DEV_NOT_READY;
	case ERROR_NOT_FOUND:
		return ISSEILIB_ERROR_CLIENT_NOT_FOUND;
	case ERROR_ACCESS_DENIED:
		return ISSEILIB_ERROR_PERMISSION_DENIED;
	case ERROR_OPERATION_ABORTED:
		return ISSEILIB_ERROR_ABORT;
	case ERROR_CONNECTION_COUNT_LIMIT:
		return ISSEILIB_ERROR_BUSY;
	case ERROR_CONNECTION_INVALID:
		return ISSEILIB_ERROR_DISCONNECTED;
	default:
		return ISSEILIB_ERROR_GENERAL;
	}
}

static uint32_t create_file(IN OUT struct issei_int_handle* int_handle)
{
	uint32_t status;

	int_handle->handle = CreateFileA(int_handle->device_path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL);

	if (int_handle->handle == INVALID_HANDLE_VALUE)
	{
		DWORD err = GetLastError();
		ERRPRINT(int_handle, "Error in CreateFile, error: %lu\n", err);
		if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
			status = ISSEILIB_ERROR_DEV_NOT_FOUND;
		else
			status = ISSEILIB_ERROR_DEV_NOT_READY;
	}
	else
	{
		status = ISSEILIB_SUCCESS;
	}

	return status;
}

#define MALLOC(X) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) {if(X) { HeapFree(GetProcessHeap(), 0, X); X = NULL ; } }

static uint32_t begin_overlapped(IN bool read_op, IN struct issei_int_handle* int_handle,
	IN const PVOID buffer, IN size_t bufferSize)
{
	uint32_t status;
	DWORD bytesTransferred = 0;
	BOOL optSuccessed;

	if (int_handle->handle == INVALID_HANDLE_VALUE)
	{
		status = ISSEILIB_ERROR_INVALID_PARAM;
		ERRPRINT(int_handle, "One of the parameters was illegal\n");
		goto Cleanup;
	}

	if (read_op)
	{
		optSuccessed = ReadFile(int_handle->handle, buffer, (DWORD)bufferSize, &bytesTransferred,
			int_handle->evt[ISSEI_WIN_EVT_READ]);
	}
	else
	{
		optSuccessed = WriteFile(int_handle->handle, buffer, (DWORD)bufferSize, &bytesTransferred,
			int_handle->evt[ISSEI_WIN_EVT_WRITE]);
	}

	if (!optSuccessed)
	{
		DWORD err = GetLastError();

		if (ERROR_IO_PENDING != err)
		{
			status = err_win32_to_issei(err);
			ERRPRINT(int_handle, "Error in ReadFile/Write, error: %d, status: %u\n", err, status);
		}
		else
		{
			DBGPRINT(int_handle, "Pending in ReadFile/Write");
			status = ISSEILIB_SUCCESS;
		}
	}
	else
	{
		status = ISSEILIB_SUCCESS;
	}

Cleanup:

	return status;
}

static uint32_t end_overlapped(IN bool read_op, IN struct issei_int_handle* int_handle, IN DWORD timeout,
	OUT OPTIONAL LPDWORD pNumberOfBytesTransferred)
{
	uint32_t status;
	DWORD err;

	if (int_handle->handle == INVALID_HANDLE_VALUE)
	{
		status = ISSEILIB_ERROR_INVALID_PARAM;
		ERRPRINT(int_handle, "One of the parameters was illegal\n");
		goto Cleanup;
	}
	if (timeout == 0)
		timeout = INFINITE;

	// wait for the answer
	err = WaitForSingleObject(int_handle->evt[ (read_op) ? ISSEI_WIN_EVT_READ: ISSEI_WIN_EVT_WRITE]->hEvent, timeout);
	switch(err)
	{
	case WAIT_TIMEOUT:
		status = ISSEILIB_ERROR_TIMEOUT;
		DBGPRINT(int_handle, "WaitForSingleObject timed out!\n");
		CancelIoEx(int_handle->handle, int_handle->evt[(read_op) ? ISSEI_WIN_EVT_READ : ISSEI_WIN_EVT_WRITE]);
		goto Cleanup;
	case WAIT_ABANDONED:
		status = ISSEILIB_ERROR_GENERAL;
		ERRPRINT(int_handle, "WaitForSingleObject meets abandoned event!\n");
		goto Cleanup;
	case WAIT_OBJECT_0:
		break;
	default:
		err = GetLastError();
		status = err_win32_to_issei(err);
		ERRPRINT(int_handle, "WaitForSingleObject reported error: %d, status: %u\n", err, status);
		goto Cleanup;
	}

	// last parameter is true b/c if we're here the operation has been completed)
	if (!GetOverlappedResult(int_handle->handle,
		int_handle->evt[(read_op) ? ISSEI_WIN_EVT_READ : ISSEI_WIN_EVT_WRITE],
		pNumberOfBytesTransferred, TRUE))
	{
		err = GetLastError();
		status = err_win32_to_issei(err);
		ERRPRINT(int_handle, "Error in GetOverlappedResult, error: %d, status: %u\n", err, status);
		goto Cleanup;
	}

	status = ISSEILIB_SUCCESS;

Cleanup:

	return status;
}

static uint32_t get_device_path(IN struct issei_int_handle* int_handle, IN LPCGUID interface_guid,
	IN OUT char* path, IN SIZE_T pathSize)
{
	CONFIGRET cr;
	char* deviceInterfaceList = NULL;
	ULONG         deviceInterfaceListLength = 0;
	errno_t       hr;
	uint32_t     status = ISSEILIB_ERROR_GENERAL;

	if (interface_guid == NULL || path == NULL || pathSize < 1)
	{
		status = ISSEILIB_ERROR_GENERAL;
		ERRPRINT(int_handle, "One of the parameters was illegal");
		goto Cleanup;
	}

	path[0] = 0x00;

	cr = CM_Get_Device_Interface_List_SizeA(
		&deviceInterfaceListLength,
		(LPGUID)interface_guid,
		NULL,
		CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
	if (cr != CR_SUCCESS)
	{
		ERRPRINT(int_handle, "Error 0x%x retrieving device interface list size.\n", cr);
		status = ISSEILIB_ERROR_GENERAL;
		goto Cleanup;
	}

	if (deviceInterfaceListLength <= 1)
	{
		status = ISSEILIB_ERROR_DEV_NOT_FOUND;
		ERRPRINT(int_handle, "CM_Get_Device_Interface_List_SizeA returned status %d", GetLastError());
		goto Cleanup;
	}

	deviceInterfaceList = (char*)malloc(deviceInterfaceListLength * sizeof(char));
	if (deviceInterfaceList == NULL)
	{
		ERRPRINT(int_handle, "Error allocating memory for device interface list.\n");
		status = ISSEILIB_ERROR_GENERAL;
		goto Cleanup;
	}
	ZeroMemory(deviceInterfaceList, deviceInterfaceListLength * sizeof(char));

	cr = CM_Get_Device_Interface_ListA(
		(LPGUID)interface_guid,
		NULL,
		deviceInterfaceList,
		deviceInterfaceListLength,
		CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
	if (cr != CR_SUCCESS)
	{
		ERRPRINT(int_handle, "Error 0x%x retrieving device interface list.\n", cr);
		status = ISSEILIB_ERROR_GENERAL;
		goto Cleanup;
	}

	hr = strcpy_s(path, pathSize, deviceInterfaceList);
	if (hr)
	{
		status = ISSEILIB_ERROR_GENERAL;
		ERRPRINT(int_handle, "Error: strcpy_s failed with error 0x%x", hr);
		goto Cleanup;
	}

	status = ISSEILIB_SUCCESS;

Cleanup:
	if (deviceInterfaceList != NULL)
	{
		free(deviceInterfaceList);
	}

	return status;
}

static uint32_t send_ioctl(IN struct issei_int_handle* int_handle, IN DWORD ioControlCode,
	IN LPVOID pInBuffer, IN DWORD inBufferSize,
	IN LPVOID pOutBuffer, IN DWORD outBufferSize, OUT LPDWORD pBytesRetuned)
{
	uint32_t status;
	DWORD err;

	if (!DeviceIoControl(int_handle->handle, ioControlCode,
		pInBuffer, inBufferSize,
		pOutBuffer, outBufferSize,
		pBytesRetuned, int_handle->evt[ISSEI_WIN_EVT_IOCTL]))
	{
		err = GetLastError();
		// it's ok to get an error here, because it's overlapped
		if (ERROR_IO_PENDING != err) {
			status = err_win32_to_issei(err);
			ERRPRINT(int_handle, "Error in DeviceIoControl, error: %d, status: %u\n", err, status);
			goto Cleanup;
		}
	}

	if (!GetOverlappedResult(int_handle->handle, int_handle->evt[ISSEI_WIN_EVT_IOCTL], pBytesRetuned, TRUE))
	{
		err = GetLastError();
		status = err_win32_to_issei(err);
		if (status == ISSEILIB_ERROR_BUSY || status == ISSEILIB_ERROR_CLIENT_NOT_FOUND)
			DBGPRINT(int_handle, "Error in GetOverlappedResult, error: %d, status: %u\n", err, status);
		else
			ERRPRINT(int_handle, "Error in GetOverlappedResult, error: %d, status: %u\n", err, status);
		goto Cleanup;
	}

	status = ISSEILIB_SUCCESS;

Cleanup:

	return status;
}

/* Internal API */

#define DEBUG_MSG_LEN 1024
void __issei_print(IN bool err_print, IN const char* fmt, ...)
{
	char msg[DEBUG_MSG_LEN + 1];
	va_list varl;
	va_start(varl, fmt);
	vsprintf_s(msg, DEBUG_MSG_LEN, fmt, varl);
	va_end(varl);

#ifdef SYSLOG
	(err_print);
	OutputDebugStringA(msg);
#else
	fprintf((err_print) ? stderr : stdout, "%s", msg);
#endif /* SYSLOG */
}

void __issei_deinit_internal_overlapped(IN OUT struct issei_int_handle* int_handle)
{
	for (size_t i = 0; i < ISSEI_WIN_MAX_EVT; i++)
	{
		if (int_handle->evt[i])
		{
			if (int_handle->evt[i]->hEvent)
				CloseHandle(int_handle->evt[i]->hEvent);
			FREE(int_handle->evt[i]);
			int_handle->evt[i] = NULL;
		}
	}
}

uint32_t __issei_init_internal_overlapped(IN OUT struct issei_int_handle* int_handle)
{
	for (size_t i = 0; i < ISSEI_WIN_MAX_EVT; i++)
	{
		int_handle->evt[i] = (LPOVERLAPPED)MALLOC(sizeof(OVERLAPPED));
		if (!int_handle->evt[i])
		{
			ERRPRINT(int_handle, "Error in MALLOC, error: %d\n", GetLastError());
			goto err;
		}

		int_handle->evt[i]->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!int_handle->evt[i]->hEvent)
		{
			ERRPRINT(int_handle, "Error in CreateEvent, error: %d\n", GetLastError());
			goto err;
		}
	}
	return ISSEILIB_SUCCESS;
err:
	__issei_deinit_internal_overlapped(int_handle);
	return ISSEILIB_ERROR_GENERAL;
}

uint32_t __issei_init_internal_path(IN OUT struct issei_int_handle* int_handle, IN const char* device_path)
{
	uint32_t status;

	status = __issei_init_internal_overlapped(int_handle);
	if (status != ISSEILIB_SUCCESS)
	{
		return status;
	}

	int_handle->device_path = _strdup(device_path);
	if (int_handle->device_path == NULL)
	{
		ERRPRINT(int_handle, "Error in in device path copy\n");
		status = ISSEILIB_ERROR_GENERAL;
		goto Cleanup;
	}

	status = create_file(int_handle);
Cleanup:
	if (status != ISSEILIB_SUCCESS)
	{
		__issei_deinit_internal(int_handle);
	}
	return status;
}

uint32_t __issei_init_internal_null(IN OUT struct issei_int_handle* int_handle)
{
	char  device_path_tmp[MAX_PATH] = { 0 };
	uint32_t status;

	status = get_device_path(int_handle, &GUID_DEVINTERFACE_IsseiDriver, device_path_tmp, MAX_PATH);
	if (status != ISSEILIB_SUCCESS)
	{
		ERRPRINT(int_handle, "Error in GetDevicePath, error: %d\n", status);
		return status;
	}

	return __issei_init_internal_path(int_handle, device_path_tmp);
}

uint32_t __issei_init_internal_handle(IN OUT struct issei_int_handle* int_handle, IN ISSEILIB_DEVICE_HANDLE handle)
{
	uint32_t status;

	status = __issei_init_internal_overlapped(int_handle);
	if (status != ISSEILIB_SUCCESS)
	{
		return status;
	}

	int_handle->handle = handle;
	return ISSEILIB_SUCCESS;
}

void __issei_deinit_internal(IN OUT struct issei_int_handle *int_handle)
{
	__issei_deinit_internal_overlapped(int_handle);
	if (int_handle->close_on_exit && int_handle->handle != ISSEILIB_INVALID_DEVICE_HANDLE)
		CloseHandle(int_handle->handle);
}

uint32_t __issei_reopen(IN OUT struct issei_int_handle *int_handle)
{
	CloseHandle(int_handle->handle);
	int_handle->handle = ISSEILIB_INVALID_DEVICE_HANDLE;
	return create_file(int_handle);
}

uint32_t __issei_connect_ioctl(IN OUT struct issei_int_handle *int_handle)
{
	FW_CLIENT reply;
	DWORD bytes = 0;
	uint32_t status;

	status = send_ioctl(int_handle, (DWORD)IOCTL_ISSEI_CONNECT_CLIENT,
		&int_handle->properties.uuid, sizeof(ISSEILIB_UUID),
		&reply, sizeof(FW_CLIENT),
		&bytes);
	if (!status)
	{
		int_handle->properties.max_message_size = reply.MaxMessageLength;
		int_handle->properties.protocol_version = reply.ProtocolVersion;
		int_handle->properties.flags = reply.Flags;
	}
	return status;
}

#define CANCEL_TIMEOUT 5000
uint32_t __issei_disconnect_ioctl(IN OUT struct issei_int_handle *int_handle)
{
	DWORD bytes = 0;
	uint32_t status;

	if (CancelIoEx(int_handle->handle, NULL))
	{
		HANDLE handles[ISSEI_WIN_MAX_EVT];
		for (size_t i = 0; i < ISSEI_WIN_MAX_EVT; i++)
		{
			handles[i] = int_handle->evt[i]->hEvent;
		}
		status = WaitForMultipleObjects(ISSEI_WIN_MAX_EVT, handles, TRUE, CANCEL_TIMEOUT);
		if (status > (WAIT_OBJECT_0 + ISSEI_WIN_MAX_EVT - 1))
		{
			ERRPRINT(int_handle, "Error in WaitForMultipleObjects, error: %lu, status: %u\n",
				GetLastError(), status);
		}
	}

	status = send_ioctl(int_handle, (DWORD)IOCTL_ISSEI_DISCONNECT_CLIENT,
		NULL, 0, NULL, 0, &bytes);

	return status;
}

uint32_t __issei_driver_status_ioctl(IN OUT struct issei_int_handle *int_handle, OUT uint32_t *driver_status)
{
	DWORD bytes = 0;
	uint32_t status;

	status = send_ioctl(int_handle, (DWORD)IOCTL_ISSEI_STATUS_INFORMATION,
		NULL, 0, &driver_status, sizeof(uint32_t), &bytes);
	if (!status && (bytes != sizeof(uint32_t)))
	{
		ERRPRINT(int_handle, "Error in send_ioctl, bytesReturned: %u\n", bytes);
		status = ISSEILIB_ERROR_GENERAL;
	}

	return status;
}

uint32_t __issei_write_internal(IN OUT struct issei_int_handle *int_handle, IN const uint8_t *data, IN size_t data_size, IN uint32_t timeout)
{
	DWORD bytes = 0;
	uint32_t status;

	status = begin_overlapped(false, int_handle, (const LPVOID)data, data_size);
	if (status) {
		return status;
	}

	status = end_overlapped(false, int_handle, timeout, &bytes);
	if (status) {
		return status;
	}

	return ISSEILIB_SUCCESS;
}

uint32_t __issei_read_internal(IN OUT struct issei_int_handle *int_handle, OUT uint8_t *data, IN OUT size_t *data_size, IN uint32_t timeout)
{
	DWORD bytes = 0;
	uint32_t status;

	status = begin_overlapped(true, int_handle, (const LPVOID)data, *data_size);
	if (status) {
		return status;
	}

	status = end_overlapped(true, int_handle, timeout, &bytes);
	if (status) {
		return status;
	}

	*data_size = bytes;

	return ISSEILIB_SUCCESS;
}
