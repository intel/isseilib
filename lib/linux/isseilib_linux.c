/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Intel Corporation
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <unistd.h>

#include "isseilib.h"
#include "internal.h"
#include "isseilib_linux.h"

#include "issei.h"

#define DEBUG_MSG_LEN 1024
void __issei_print(IN bool err_print, IN const char *fmt, ...)
{
	char msg[DEBUG_MSG_LEN + 1];
	va_list varl;
	va_start(varl, fmt);
	vsnprintf(msg, DEBUG_MSG_LEN, fmt, varl);
	va_end(varl);

#ifdef SYSLOG
	syslog((err_print) ? LOG_ERR : LOG_DEBUG, "%s", msg);
#else
	fprintf((err_print) ? stderr : stdout, "%s", msg);
#endif /* SYSLOG */
}

static inline uint32_t errno2status_init(int err)
{
	switch (err) {
		case 0     : return ISSEILIB_SUCCESS;
		case ENOENT: return ISSEILIB_ERROR_DEV_NOT_FOUND;
		case ENAMETOOLONG: return ISSEILIB_ERROR_DEV_NOT_FOUND;
		case EBUSY : return ISSEILIB_ERROR_BUSY;
		case ENODEV: return ISSEILIB_ERROR_DEV_NOT_READY;
		case ETIME : return ISSEILIB_ERROR_TIMEOUT;
		case EACCES: return ISSEILIB_ERROR_PERMISSION_DENIED;
		case ECANCELED: return ISSEILIB_ERROR_ABORT;
		default    : return ISSEILIB_ERROR_GENERAL;
	}
}

static inline uint32_t errno2status(int err)
{
	switch (err) {
		case 0     : return ISSEILIB_SUCCESS;
		case ENOTTY: return ISSEILIB_ERROR_CLIENT_NOT_FOUND;
		case EBUSY : return ISSEILIB_ERROR_BUSY;
		case ENODEV: return ISSEILIB_ERROR_DEV_NOT_READY;
		case ENOTCONN: return ISSEILIB_ERROR_DISCONNECTED;
		case ETIME : return ISSEILIB_ERROR_TIMEOUT;
		case EACCES: return ISSEILIB_ERROR_PERMISSION_DENIED;
		case EFBIG : return ISSEILIB_ERROR_SMALL_BUFFER;
		case ECANCELED: return ISSEILIB_ERROR_ABORT;
		default    : return ISSEILIB_ERROR_GENERAL;
	}
}

static inline int __issei_poll(struct issei_int_handle *int_handle,
			       bool on_read, unsigned long timeout)
{
	int ltimeout;
	int rc;
	struct pollfd pfd[2];
	pfd[0].fd = int_handle->handle;
	pfd[0].events = (on_read) ? POLLIN : POLLOUT;
	pfd[1].fd = int_handle->cancel_pipe[0];
	pfd[1].events = POLLIN;

	if (timeout > INT_MAX)
		return EOVERFLOW;

	ltimeout = (timeout) ? (int)timeout : -1;

	errno = 0;
	rc = poll(pfd, 2, ltimeout);
	if (rc < 0)
		return errno;
	if (rc == 0)
		return ETIME;
	if (pfd[1].revents != 0)
		return ECANCELED;
	return 0;
}

int __issei_init_pipe(IN OUT struct issei_int_handle* int_handle)
{
	int ret;

	ret = pipe(int_handle->cancel_pipe);
	if (ret)
	{
		ERRPRINT(int_handle, "Error in pipe creation ret=%d\n", ret);
	}
	return ret;
}

uint32_t __issei_init_internal_path(IN OUT struct issei_int_handle* int_handle, IN const char* device_path)
{
	uint32_t status;

	/* to avoid incidental close of descriptor zero on cleanup */
	int_handle->cancel_pipe[0] = -1;
	int_handle->cancel_pipe[1] = -1;

	int_handle->device_path = strdup(device_path);
	if (int_handle->device_path == NULL)
	{
		ERRPRINT(int_handle, "Error in device path copy\n");
		return ISSEILIB_ERROR_GENERAL;
	}

	errno = 0;
	int_handle->handle = open(int_handle->device_path, O_RDWR | O_CLOEXEC);
	status = errno2status_init(errno);
	if (status)
	{
		ERRPRINT(int_handle, "Error in open errno=%d, status=%d\n", errno, status);
		return status;
	}
	if (__issei_init_pipe(int_handle))
	{
		__issei_deinit_internal(int_handle);
		return ISSEILIB_ERROR_GENERAL;
	}
	return ISSEILIB_SUCCESS;
}

uint32_t __issei_init_internal_null(IN OUT struct issei_int_handle* int_handle)
{
	 const char* device_path_int = ISSEILIB_LINUX_DEF_DEV;

	 return __issei_init_internal_path(int_handle, device_path_int);
}

uint32_t __issei_init_internal_handle(IN OUT struct issei_int_handle* int_handle, IN ISSEILIB_DEVICE_HANDLE handle)
{
	/* to avoid incidental close of descriptor zero on cleanup */
	int_handle->cancel_pipe[0] = -1;
	int_handle->cancel_pipe[1] = -1;

	int_handle->handle = handle;
	if (__issei_init_pipe(int_handle))
	{
		__issei_deinit_internal(int_handle);
		return ISSEILIB_ERROR_GENERAL;
	}
	return ISSEILIB_SUCCESS;
}

void __issei_deinit_internal(IN OUT struct issei_int_handle *int_handle)
{
	close(int_handle->cancel_pipe[0]);
	close(int_handle->cancel_pipe[1]);
	int_handle->cancel_pipe[0] = -1;
	int_handle->cancel_pipe[1] = -1;

	if (int_handle->close_on_exit && int_handle->handle != ISSEILIB_INVALID_DEVICE_HANDLE)
	{
		close(int_handle->handle);
		int_handle->handle = ISSEILIB_INVALID_DEVICE_HANDLE;
	}
}

uint32_t __issei_reopen(IN OUT struct issei_int_handle *int_handle)
{
	uint32_t status;

	close(int_handle->handle);
	int_handle->handle = ISSEILIB_INVALID_DEVICE_HANDLE;

	errno = 0;
	int_handle->handle = open(int_handle->device_path, O_RDWR | O_CLOEXEC);
	status = errno2status_init(errno);
	if (status)
	{
		ERRPRINT(int_handle, "Error in open errno=%d, status=%d\n", errno, status);
	}
	return status;
}

uint32_t __issei_connect_ioctl(IN OUT struct issei_int_handle *int_handle)
{
	struct issei_connect_client_data data;
	uint32_t status;
	int rc;

	COPY_UUID(data.in_client_uuid, int_handle->properties.uuid);

	errno = 0;
	rc = ioctl(int_handle->handle, IOCTL_ISSEI_CONNECT_CLIENT, &data);
	status = errno2status(errno);
	if (rc == -1)
	{
		if (status == ISSEILIB_ERROR_CLIENT_NOT_FOUND ||
		    status == ISSEILIB_ERROR_BUSY)
			DBGPRINT(int_handle, "Error in ioctl, errno: %d error: %u\n", errno, status);
		else
			ERRPRINT(int_handle, "Error in ioctl, errno: %d error: %u\n", errno, status);
	}
	else
	{
		int_handle->properties.max_message_size = data.out_client_properties.max_msg_length;
		int_handle->properties.protocol_version = data.out_client_properties.protocol_version;
		int_handle->properties.flags = data.out_client_properties.flags;
	}
	return status;
}

uint32_t __issei_disconnect_ioctl(IN OUT struct issei_int_handle *int_handle)
{
	const char buf[] = "X";
	uint32_t status;
	int rc;

	DBGPRINT(int_handle, "write X\n");
	if (write(int_handle->cancel_pipe[1], buf, sizeof(buf)) < 0)
	{
		ERRPRINT(int_handle, "Pipe write failed\n");
	}

	errno = 0;
	rc = ioctl(int_handle->handle, IOCTL_ISSEI_DISCONNECT_CLIENT, NULL);
	status = errno2status(errno);
	if (rc == -1)
	{
		ERRPRINT(int_handle, "Error in ioctl errno=%d, status=%d\n", errno, status);
	}
	return status;
}

uint32_t __issei_driver_status_ioctl(IN OUT struct issei_int_handle *int_handle, OUT uint32_t *driver_status)
{
	uint32_t status;
	int rc;

	errno = 0;
	rc = ioctl(int_handle->handle, IOCTL_ISSEI_DRIVER_STATUS, driver_status);
	status = errno2status(errno);
	if (rc == -1)
	{
		ERRPRINT(int_handle, "Error in ioctl, errno: %d error: %u\n", errno, status);
	}
	return status;
}

uint32_t __issei_write_internal(IN OUT struct issei_int_handle *int_handle, IN const uint8_t *data,
				IN size_t data_size, IN uint32_t timeout)
{
	uint32_t status;
	int err;
	ssize_t rc;

	err = __issei_poll(int_handle, false, timeout);
	if (err) {
		status = errno2status(err);
		if (status == ISSEILIB_ERROR_TIMEOUT)
			DBGPRINT(int_handle, "poll failed, errno: %d error: %u\n", err, status);
		else
			ERRPRINT(int_handle, "poll failed, errno: %d error: %u\n", err, status);
		return status;
	}

	errno = 0;
	rc = write(int_handle->handle, data, data_size);
	status = errno2status(errno);
	if (rc > 0)
	{
		status = ((size_t)rc != data_size) ? ISSEILIB_ERROR_GENERAL : ISSEILIB_SUCCESS;
	}
       	else 
       	{
		ERRPRINT(int_handle, "Error in write, errno: %d error: %u\n", errno, status);
	}
	return status;
}

uint32_t __issei_read_internal(IN OUT struct issei_int_handle *int_handle, OUT uint8_t *data, IN OUT size_t *data_size, IN uint32_t timeout)
{
	uint32_t status;
	int err;
	ssize_t rc;

	err = __issei_poll(int_handle, true, timeout);
	if (err) {
		status = errno2status(err);
		if (status == ISSEILIB_ERROR_TIMEOUT)
			DBGPRINT(int_handle, "poll failed, errno: %d error: %u\n", err, status);
		else
			ERRPRINT(int_handle, "poll failed, errno: %d error: %u\n", err, status);
		return status;
	}

	errno = 0;
	rc = read(int_handle->handle, data, *data_size);
	status = errno2status(errno);
	if (rc > 0)
	{
		status = ISSEILIB_SUCCESS;
		*data_size = (size_t)rc;
	}
	else
	{
		ERRPRINT(int_handle, "Error in read, errno: %d error: %u\n", errno, status);
	}
	return status;
}

uint32_t __issei_get_kind(IN OUT struct issei_int_handle *int_handle,
			  OUT char *kind, IN OUT size_t *kind_size)
{
#define KIND_LEN 128
	char buf[KIND_LEN] = { 0 };
	size_t buf_size = KIND_LEN;
	int rc;

	rc = __issei_sysfs_read(int_handle, "kind", 0, buf, &buf_size);
	if (rc)
	{
		ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}
	if (buf_size)
	{
		buf[--buf_size] = '\0'; /* remove trailing newline */
	}

	if (!kind)
	{
		*kind_size = buf_size;
		return ISSEILIB_ERROR_SMALL_BUFFER;
	}
	if (buf_size >= *kind_size)
	{
		ERRPRINT(int_handle, "Buffer is too small %zu > %zu\n", buf_size, *kind_size);
		*kind_size = buf_size;
		return ISSEILIB_ERROR_SMALL_BUFFER;
	}

	memcpy(kind, buf, buf_size + 1); /* include null terminator */
	*kind_size = buf_size + 1;

	return ISSEILIB_SUCCESS;
}

uint32_t __isseilib_get_fw_status(IN OUT struct issei_int_handle *int_handle,
				  IN uint8_t register_number, OUT uint32_t *fw_status)
{
#define FWSTS_LEN 11
#define CONV_BASE 16
	char buf[FWSTS_LEN];
	size_t buf_size = FWSTS_LEN;
	unsigned long cnv;
	int rc;

	rc = __issei_sysfs_read(int_handle, "fw_status", register_number * FWSTS_LEN,
				buf, &buf_size);
	if (rc)
	{
		ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}

	if (buf_size != FWSTS_LEN - 1)
	{
		ERRPRINT(int_handle, "Can't read full buffer, only %zu\n", buf_size);
		return ISSEILIB_ERROR_GENERAL;
	}

	errno = 0;
	cnv = strtoul(buf, NULL, CONV_BASE);
	if (errno) {
		ERRPRINT(int_handle, "Error in sysfs convert, error: %d\n", errno);
		return ISSEILIB_ERROR_GENERAL;
	}
	*fw_status = (uint32_t)cnv;

	return ISSEILIB_SUCCESS;
}

uint32_t __isseilib_get_fw_version(IN OUT struct issei_int_handle *int_handle,
				   OUT struct isseilib_device_fw_version *fw_version)
{
#define VER_MAX_LEN 20
	char buf[VER_MAX_LEN] = { 0 };
	size_t buf_size = VER_MAX_LEN;
	struct isseilib_device_fw_version cnv;
	int rc;

	rc = __issei_sysfs_read(int_handle, "fw_ver", 0, buf, &buf_size);
	if (rc)
	{
		ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}

	errno = 0;
	rc = sscanf(buf, "%hu.%hu.%hu.%hu", &cnv.major, &cnv.minor, &cnv.hotfix, &cnv.build);
	if (rc != 4)
	{
		ERRPRINT(int_handle, "Error in sysfs parse, error: %d\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}

	*fw_version = cnv;

	return ISSEILIB_SUCCESS;
}

uint32_t __isseilib_get_client_list(IN OUT struct issei_int_handle *int_handle,
				    OUT struct isseilib_client_properties *client_properties,
				    IN OUT size_t *num_clients)
{
#define MAX_CL_BUF 37
	char buf[MAX_CL_BUF];
	size_t buf_size = MAX_CL_BUF;
	struct dirent **namelist = NULL;
	uint32_t status;
	int rc;
	size_t filed_clients;

	rc = __issei_sysfs_get_client_list(int_handle, &namelist);
	if (rc < 0)
	{
		ERRPRINT(int_handle, "Error in sysfs get clients error: %d\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}
	filed_clients = (size_t)rc;
	DBGPRINT(int_handle, "Found %zu clients\n", filed_clients);

	if (*num_clients < filed_clients || !client_properties)
	{
		*num_clients = filed_clients;
		status = ISSEILIB_ERROR_SMALL_BUFFER;
		goto out;
	}

	for (size_t i = 0; i < filed_clients; i++)
	{
		buf_size = MAX_CL_BUF;
		rc = __issei_sysfs_client_read(int_handle, namelist[i]->d_name,
					       "uuid", 0, buf, &buf_size);
		if (rc)
		{
			ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}
		buf[buf_size] = '\0'; /* remove trailing newline */
		if (PARSE_UUID(buf, client_properties[i].uuid))
		{
			ERRPRINT(int_handle, "Failed to parse UUID %s\n", buf);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}

		buf_size = MAX_CL_BUF;
		rc = __issei_sysfs_client_read(int_handle, namelist[i]->d_name,
					       "ver", 0, buf, &buf_size);
		if (rc)
		{
			ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}
		client_properties[i].protocol_version = (uint32_t)strtoul(buf, NULL, 10);

		buf_size = MAX_CL_BUF;
		rc = __issei_sysfs_client_read(int_handle, namelist[i]->d_name,
					       "mtu", 0, buf, &buf_size);
		if (rc)
		{
			ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}
		client_properties[i].max_message_size = (uint32_t)strtoul(buf, NULL, 10);

		buf_size = MAX_CL_BUF;
		rc = __issei_sysfs_client_read(int_handle, namelist[i]->d_name,
					       "flags", 0, buf, &buf_size);
		if (rc)
		{
			ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}
		client_properties[i].flags = (uint32_t)strtoul(buf, NULL, 10);
	}
	*num_clients = filed_clients;
	status = ISSEILIB_SUCCESS;
out:
	__issei_sysfs_free_client_list(int_handle, &namelist, filed_clients);
	return status;
}

uint32_t __isseilib_is_client_exists(IN OUT struct issei_int_handle *int_handle,
				     IN const ISSEILIB_UUID client_uuid, OUT bool *exists)
{
#define MAX_CL_BUF 37
	char buf[MAX_CL_BUF] = { 0 };
	size_t buf_size = MAX_CL_BUF;
	struct dirent **namelist = NULL;
	uint32_t status;
	int rc;
	size_t filed_clients;
	ISSEILIB_UUID uuid;

	rc = __issei_sysfs_get_client_list(int_handle, &namelist);
	if (rc < 0)
	{
		ERRPRINT(int_handle, "Error in sysfs get clients error: %d\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}
	filed_clients = (size_t)rc;

	for (size_t i = 0; i < filed_clients; i++)
	{
		buf_size = MAX_CL_BUF;
		rc = __issei_sysfs_client_read(int_handle, namelist[i]->d_name,
					       "uuid", 0, buf, &buf_size);
		if (rc)
		{
			ERRPRINT(int_handle, "Error in sysfs read, error: %d\n", rc);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}
		buf[buf_size] = '\0'; /* remove trailing newline */
		if (PARSE_UUID(buf, uuid))
		{
			ERRPRINT(int_handle, "Failed to parse UUID %s\n", buf);
			status = ISSEILIB_ERROR_GENERAL;
			goto out;
		}
		if (memcmp(uuid, client_uuid, sizeof(ISSEILIB_UUID)) == 0)
		{
			*exists = true;
			status = ISSEILIB_SUCCESS;
			goto out;
		}
	}
	*exists = false;
	status = ISSEILIB_SUCCESS;
out:
	__issei_sysfs_free_client_list(int_handle, &namelist, filed_clients);
	return status;
}
