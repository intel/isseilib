/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2024 Intel Corporation
 */
 /*! \file internal.h
  *  \brief issei internal functions
  */

#ifndef _ISSEI_INTERNAL_H_
#define _ISSEI_INTERNAL_H_

#include "isseilib.h"

enum issei_client_state
{
	ISSEI_CLIENT_STATE_NONE,
	ISSEI_CLIENT_STATE_CONNECTED,
	ISSEI_CLIENT_STATE_FAILED
};

#define ISSEI_MAX_FW_STATUS 6

#ifdef _WIN32
	#define ISSEI_WIN_EVT_IOCTL 0
	#define ISSEI_WIN_EVT_READ  1
	#define ISSEI_WIN_EVT_WRITE 2
	#define ISSEI_WIN_MAX_EVT 3
#else /* _WIN32 */
	#define ISSEI_WIN_CANCEL_PIPES_NUM 2
#endif /* !_WIN32 */

struct issei_int_handle
{
	char *device_path;
	ISSEILIB_DEVICE_HANDLE handle;
	bool close_on_exit; /**< close handle on exit */
	enum issei_client_state state;
	struct isseilib_client_properties properties;
#ifdef _WIN32
	LPOVERLAPPED evt[ISSEI_WIN_MAX_EVT]; /**< event for executing async */
#else /* _WIN32 */
	int cancel_pipe[ISSEI_WIN_CANCEL_PIPES_NUM];
#endif /* !_WIN32 */
	enum isseilib_log_level log_level; /**< Log level */
	isseilib_log_callback log_callback; /**< Log callback */
};

uint32_t __issei_init_internal_null(IN OUT struct issei_int_handle *int_handle);
uint32_t __issei_init_internal_path(IN OUT struct issei_int_handle* int_handle, IN const char* device_path);
uint32_t __issei_init_internal_handle(IN OUT struct issei_int_handle* int_handle, IN ISSEILIB_DEVICE_HANDLE handle);
void __issei_deinit_internal(IN OUT struct issei_int_handle *int_handle);

uint32_t __issei_reopen(IN OUT struct issei_int_handle *int_handle);

uint32_t __issei_connect_ioctl(IN OUT struct issei_int_handle *int_handle);
uint32_t __issei_disconnect_ioctl(IN OUT struct issei_int_handle *int_handle);
uint32_t __issei_driver_status_ioctl(IN OUT struct issei_int_handle *int_handle, OUT uint32_t *driver_status);

uint32_t __issei_get_kind(IN OUT struct issei_int_handle *int_handle,
			  OUT char *kind, IN OUT size_t *kind_size);

uint32_t __issei_write_internal(IN OUT struct issei_int_handle *int_handle, IN const uint8_t *data, IN size_t data_size, IN uint32_t timeout);

uint32_t __issei_read_internal(IN OUT struct issei_int_handle *int_handle, OUT uint8_t *data, IN OUT size_t *data_size, IN uint32_t timeout);

uint32_t __isseilib_get_fw_status(IN OUT struct issei_int_handle *int_handle,
				  IN uint8_t register_number, OUT uint32_t *fw_status);
uint32_t __isseilib_get_fw_version(IN OUT struct issei_int_handle *int_handle,
				   OUT struct isseilib_device_fw_version *fw_version);

uint32_t __isseilib_get_client_list(IN OUT struct issei_int_handle *int_handle,
				    OUT struct isseilib_client_properties *client_properties,
				    IN OUT size_t *num_clients);

uint32_t __isseilib_is_client_exists(IN OUT struct issei_int_handle *int_handle,
				     IN const ISSEILIB_UUID client_uuid, OUT bool *exists);

/* Logging*/
void __issei_print(IN bool err_print, IN const char *fmt, ...);

#define DEBUG_PRINT_ISSE_PREFFIX "ISSEILIB: (%s:%s():%d) "

#define DBGPRINT(h, _x_, ...) \
do { \
	if ((h)->log_level >= ISSEILIB_LOG_LEVEL_VERBOSE) { \
		if ((h)->log_callback) \
			(h)->log_callback(false, DEBUG_PRINT_ISSE_PREFFIX _x_, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
		else \
			__issei_print(false, DEBUG_PRINT_ISSE_PREFFIX _x_, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
	} \
} while(0)

#define ERRPRINT(h, _x_, ...) \
do { \
	if ((h)->log_level >= ISSEILIB_LOG_LEVEL_ERROR) { \
		if ((h)->log_callback) \
			(h)->log_callback(true, DEBUG_PRINT_ISSE_PREFFIX _x_, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
		else \
			__issei_print(true, DEBUG_PRINT_ISSE_PREFFIX _x_, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
	} \
} while(0)

#define FUNC_ENTRY(h)         DBGPRINT(h, "Entry\n")
#define FUNC_EXIT(h, status)  DBGPRINT(h, "Exit with status: %d\n", status)

/* UUID */

static inline void COPY_UUID(ISSEILIB_UUID dst, const ISSEILIB_UUID src)
{
	memcpy(dst, src, sizeof(ISSEILIB_UUID));
}

int PARSE_UUID(const char* src, ISSEILIB_UUID dst);
int PARSE_UUIDW(const wchar_t* src, ISSEILIB_UUID dst);
int PRINT_UUID(const ISSEILIB_UUID src, char *dst, size_t dst_size);

#endif /*_ISSEI_INTERNAL_H_*/
