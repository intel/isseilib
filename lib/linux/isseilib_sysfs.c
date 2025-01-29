/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023 Intel Corporation
 */
#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "internal.h"
#include "isseilib_linux.h"

static int __issei_sysfs_create_path(struct issei_int_handle *int_handle, const char *dir, const char *fname,
				     char *path, size_t path_size)
{
	char *device;

	if (int_handle->device_path) {
		device = strstr(int_handle->device_path, ISSEILIB_LINUX_DEF_DEV_PREFIX);
		if (!device) {
			ERRPRINT(int_handle, "Device does not start with '%s'\n",
				 ISSEILIB_LINUX_DEF_DEV_PREFIX);
			return -EINVAL;
		}
		device += sizeof(ISSEILIB_LINUX_DEF_DEV_PREFIX) - 1;
	} else {
		device = ISSEILIB_LINUX_DEF_DEV_NAME;
	}

	if (dir)
	{
		if (snprintf(path, path_size, "/sys/class/issei/%s/%s/%s", device, dir, fname) < 0)
			return -EINVAL;
	}
	else
	{
		if (snprintf(path, path_size, "/sys/class/issei/%s/%s", device, fname) < 0)
			return -EINVAL;
	}
	path[path_size - 1] = '\0';

	return 0;
}

int __issei_sysfs_read(struct issei_int_handle *int_handle,
		       const char *fname, off_t offset, char *buf, size_t *buf_size)
{
	char path[PATH_MAX];
	int fd;
	size_t olen = *buf_size;
	ssize_t len;
	int ret;

	*buf_size = 0;

	ret = __issei_sysfs_create_path(int_handle, NULL, fname, path, PATH_MAX);
	if (ret)
		return ret;

	errno = 0;
	fd = open(path, O_CLOEXEC, O_RDONLY);
	if (fd == -1)
	{
		ret = -errno;
		ERRPRINT(int_handle, "Open of %s failed, err = %d\n", path, ret);
		return ret;
	}

	errno = 0;
	len = pread(fd, buf, olen - 1, offset);
	ret = -errno;
	close(fd);
	if (len == -1) {
		ERRPRINT(int_handle, "Read of %s at offset %zu failed, err = %d\n",
			path, offset, ret);
		return ret;
	}

	buf[len] = '\0';
	*buf_size = (size_t)len;

	return 0;
}

static const char *__issei_fw_cl = "fw_client:";
static int __issei_sysfs_fw_client_filter(const struct dirent *dent)
{
	return (strlen(dent->d_name) >= strlen(__issei_fw_cl)) &&
	       (strncmp(dent->d_name, __issei_fw_cl, strlen(__issei_fw_cl)) == 0);
}


int __issei_sysfs_get_client_list(struct issei_int_handle *int_handle, struct dirent ***namelist)
{
	char path[PATH_MAX];
	int ret;

	ret = __issei_sysfs_create_path(int_handle, NULL, "", path, PATH_MAX);
	if (ret)
		return ret;

	return scandir(path, namelist, __issei_sysfs_fw_client_filter, NULL);
}

void __issei_sysfs_free_client_list(struct issei_int_handle *int_handle,
				    struct dirent ***namelist, size_t n)
{
	(void)(int_handle);

	if (!n)
		return;
	while (n--)
		free((*namelist)[n]);
	free(*namelist);
}

int __issei_sysfs_client_read(struct issei_int_handle *int_handle, const char *client_name,
			      const char *fname, off_t offset, char *buf, size_t *buf_size)
{
	char path[PATH_MAX];
	int fd;
	size_t olen = *buf_size;
	ssize_t len;
	int ret;

	*buf_size = 0;

	ret = __issei_sysfs_create_path(int_handle, client_name, fname, path, PATH_MAX);
	if (ret)
		return ret;

	errno = 0;
	fd = open(path, O_CLOEXEC, O_RDONLY);
	if (fd == -1)
	{
		ret = -errno;
		ERRPRINT(int_handle, "Open of %s failed, err = %d\n", path, ret);
		return ret;
	}

	errno = 0;
	len = pread(fd, buf, olen - 1, offset);
	ret = -errno;
	close(fd);
	if (len < 0) {
		ERRPRINT(int_handle, "Read of %s at offset %zu failed, err = %d\n",
			path, offset, ret);
		return ret;
	}
	buf[len] = '\0';

	*buf_size = (size_t)len;

	return 0;
}
