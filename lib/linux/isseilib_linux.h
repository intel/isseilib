/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023 Intel Corporation
 */
#ifndef ISSEILIB_LINUX_H
#define ISSEILIB_LINUX_H

/*! Default name of issei device
 */
#define ISSEILIB_LINUX_DEF_DEV_NAME "issei0"

/*! Default path to issei device
 */
#define ISSEILIB_LINUX_DEF_DEV_PREFIX "/dev/"
#define ISSEILIB_LINUX_DEF_DEV (ISSEILIB_LINUX_DEF_DEV_PREFIX ISSEILIB_LINUX_DEF_DEV_NAME)

struct dirent;
struct issei_int_handle;

int __issei_sysfs_read(struct issei_int_handle *int_handle,
		       const char *fname, off_t offset, char *buf, size_t *buf_size);

int __issei_sysfs_get_client_list(struct issei_int_handle *int_handle, struct dirent ***namelist);
void __issei_sysfs_free_client_list(struct issei_int_handle *int_handle,
				    struct dirent ***namelist, size_t n);
int __issei_sysfs_client_read(struct issei_int_handle *int_handle, const char *client_name,
			      const char *fname, off_t offset, char *buf, size_t *buf_size);

#endif /* ISSEILIB_LINUX_H */
