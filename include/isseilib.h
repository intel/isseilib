/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Intel Corporation
 */
/*! \file isseilib.h
 *  \brief issei access library API
 */
#ifndef ISSEILIB_H
#define ISSEILIB_H

#ifdef __cplusplus
extern "C" {
#endif

/** UUID object */
typedef unsigned char ISSEILIB_UUID[16];

/** UUID definition macro */
#define DEFINE_ISSEILIB_UUID(__name__, a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)         \
	static const ISSEILIB_UUID __name__ = {                                    \
		((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
		((b) >> 8) & 0xff, (b) & 0xff,                                         \
		((c) >> 8) & 0xff, (c) & 0xff,                                         \
		(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }

#ifdef _WIN32
	#include <Windows.h>

/*! @cond suppress_warnings */
	#ifndef ISSEILIB_DLL
		#define ISSEILIB_DLL_API
	#else /* ISSEILIB_DLL */
		#ifdef ISSEILIB_DLL_EXPORT
				#define ISSEILIB_DLL_API __declspec(dllexport)
		#else
				#define ISSEILIB_DLL_API __declspec(dllimport)
		#endif /* ISSEILIB_DLL_EXPORT */
	#endif /* ISSEILIB_DLL */
/*! @endcond */
	/** Device handle to access ISSE system device */
	#define ISSEILIB_DEVICE_HANDLE HANDLE
	/** Invalid Device handle definition */
	#define ISSEILIB_INVALID_DEVICE_HANDLE ((void*)0)
#else /* _WIN32 */
/*! @cond suppress_warnings */
	#ifndef IN
		#define IN
	#endif
	#ifndef OUT
		#define OUT
	#endif
	#ifndef OPTIONAL
		#define OPTIONAL
	#endif
	#ifndef ISSEILIB_DLL
		#define ISSEILIB_DLL_API
	#else /*! ISSEILIB_DLL */
		#ifdef ISSEILIB_DLL_EXPORT
			#define ISSEILIB_DLL_API __attribute__((__visibility__("default")))
		#else
			#define ISSEILIB_DLL_API
		#endif /* ISSEILIB_DLL_EXPORT */
	#endif /* ISSEILIB_DLL */
/*! @endcond */
	/** Device handle to access ISSE system device */
	#define ISSEILIB_DEVICE_HANDLE int
	/** Invalid Device handle definition */
	#define ISSEILIB_INVALID_DEVICE_HANDLE (-1)
#endif /* _WIN32 */

#include <stdint.h>
#include <stdbool.h>

/*! ISEE firmware version structure */
struct isseilib_device_fw_version
{
	uint16_t major; /**< Major version part */
	uint16_t minor; /**< Minor version part */
	uint16_t hotfix; /**< Hotfix version part */
	uint16_t build; /**< Build version part */
};

/*! Client properties structure */
struct isseilib_client_properties
{
	ISSEILIB_UUID uuid; /**< Client UUID */
	uint32_t protocol_version; /**< Client protocol version */
	uint32_t max_message_size; /**< Client MTU (maximum message size) */
	uint32_t flags; /**< Client flags bitmap */
};

/*! Status codes enumeration */
enum isseilib_status
{
	ISSEILIB_SUCCESS = 0,
	ISSEILIB_ERROR_GENERAL = 1,
	ISSEILIB_ERROR_SMALL_BUFFER = 2,
	ISSEILIB_ERROR_INVALID_PARAM = 3,
	ISSEILIB_ERROR_TIMEOUT = 4,
	ISSEILIB_ERROR_PERMISSION_DENIED = 5,
	ISSEILIB_ERROR_DEV_NOT_FOUND = 6,
	ISSEILIB_ERROR_DEV_NOT_READY = 7,
	ISSEILIB_ERROR_CLIENT_NOT_FOUND = 8,
	ISSEILIB_ERROR_DISCONNECTED = 9,
	ISSEILIB_ERROR_BUSY = 10,
	ISSEILIB_ERROR_ABORT = 11,
};

/*! Log level */
enum isseilib_log_level
{
	ISSEILIB_LOG_LEVEL_QUIET = 0,   /**< no log prints */
	ISSEILIB_LOG_LEVEL_ERROR = 1,   /**< error log prints */
	ISSEILIB_LOG_LEVEL_VERBOSE = 2, /**< verbose log prints */
	ISSEILIB_LOG_LEVEL_MAX = 3,     /**< upper sentinel */
};

/*! Log callback function format */
typedef void(*isseilib_log_callback)(bool is_error, const char* fmt, ...);

/*! Internal library handle */
#define isseilib_handle void*

/*! Device address passed to the init function */
struct isseilib_device_address {
	/*! Device address type */
	enum {
		ISSEILIB_DEVICE_TYPE_NONE = 0, /**< Select first available device */
		ISSEILIB_DEVICE_TYPE_PATH = 1, /**< Use device by path (char*) */
		ISSEILIB_DEVICE_TYPE_HANDLE = 2, /**< Use device by pre-opend handle */
		ISSEILIB_DEVICE_TYPE_MAX = 3, /**< upper sentinel */
	} type;
	/*! Device address */
	union {
		const char* path; /** < Path to device */
		ISSEILIB_DEVICE_HANDLE handle; /**< Pre-opend handle */
	} data;
};

/* Function declarations */

/*! Initializes a ISSEI connection
 *  \param handle A handle to the ISSEI device. All subsequent calls to the lib's functions
 *         must be with this handle
 *  \param device device address structure
 *  \param log_level log level to set (from enum #isseilib_log_level)
 *  \param log_callback pointer to function to run for log write, set NULL to use built-in function
 *
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_init(IN OUT isseilib_handle *handle,
	IN const struct isseilib_device_address device,
	IN uint32_t log_level, IN OPTIONAL isseilib_log_callback log_callback);

/*! Closes the session to ISEEI driver
 *  \param handle The handle of the session to close.
 */
ISSEILIB_DLL_API void isseilib_deinit(IN OUT isseilib_handle *handle);

/*! Connects to the ISSEI client
 *  \param handle A handle to the ISEEI device
 *  \param client_properties Client properties structure, the uuid field should be filled by caller,
 *                           all other fields filled by library on successful connect.
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_connect(IN isseilib_handle *handle, IN OUT struct isseilib_client_properties *client_properties);

/*! Disconnects from the ISSEI client
 *  Make sure that you call this function as soon as you are done with the device,
 *  as other clients might be blocked until the session is closed.
 *  \param handle A handle to the ISEEI device
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_disconnect(IN isseilib_handle *handle);

/*! Writes the specified buffer to the ISSEI device.
 *  \param handle The handle of the session to write to.
 *  \param data A pointer to the buffer containing the data to be written to the device.
 *  \param data_size The number of bytes to be written.
 *  \param timeout The timeout to complete write in milliseconds, zero for infinite
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_write(IN isseilib_handle *handle, IN const uint8_t *data, IN size_t data_size, IN OPTIONAL uint32_t timeout);

/*! Read data from the ISSEI device synchronously.
 *  \param handle The handle of the session to read from.
 *  \param data A pointer to a buffer that receives the data read from the ISSEI device.
 *  \param data_size Size of buffer provided by caller, filled by actually received data size by library.
 *  \param timeout The timeout to complete read in milliseconds, zero for infinite
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_read(IN isseilib_handle *handle, uint8_t *data, IN OUT size_t *data_size, IN OPTIONAL uint32_t timeout);

/*! Read ISSEI driver status
 *  \param handle A handle to the ISEEI device
 *  \param driver_status Memory to put the status obtained from driver.
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_get_status(IN isseilib_handle *handle, OUT uint32_t *driver_status);

/*! Read ISSEI device kind
 *  \param handle A handle to the ISEEI device
 *  \param kind Memory to put the kind obtained from driver.
 *  \param kind_size Size of kind memory buffer providd by caller, filled with actual size of data received (including terminating null)
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_get_kind(IN isseilib_handle *handle, OUT char *kind, IN OUT size_t *kind_size);

/*! Read ISSEI FW version
 *  \param handle A handle to the ISEEI device
 *  \param fw_version Memory to put the FW version.
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_get_fw_version(IN isseilib_handle *handle, OUT struct isseilib_device_fw_version *fw_version);

/*! Read ISSEI FW status
 *  \param handle A handle to the ISEEI device
 *  \param register_number The FW status register number (zero-based).
 *  \param fw_status Memory to put the FW status data.
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_get_fw_status(IN isseilib_handle *handle, IN uint8_t register_number, OUT uint32_t *fw_status);

/*! Read the ISSEI FW client list
 *  \param handle A handle to the ISEEI device
 *  \param client_properties Memory to put the FW client properties.
 *  \param num_clients Number of client that fit in buffer provided by caller, filled by actually received clients number by library.
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_get_client_list(IN isseilib_handle *handle, OUT struct isseilib_client_properties *client_properties, IN OUT size_t *num_clients);

/*! Check that ISSEI FW client exists
 *  \param handle A handle to the ISEEI device
 *  \param client_uuid UUID of the FW client.
 *  \param exists Memory to put boolean true if client exists, false otherwise.
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_is_client_exists(IN isseilib_handle *handle, IN const ISSEILIB_UUID client_uuid, OUT bool *exists);

/*! Set log level
 *
 *  \param handle A handle to the ISEEI device
 *  \param log_level log level to set
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_set_log_level(IN isseilib_handle *handle, IN uint32_t log_level);

/*! Retrieve current log level
 *
 *  \param handle A handle to the ISEEI device
 *  \param log_level log level to fill
 *  \return 0 if successful, otherwise error code
 */
ISSEILIB_DLL_API uint32_t isseilib_get_log_level(IN isseilib_handle *handle, OUT uint32_t *log_level);

/*! Set log callback
 *
 *  \param handle A handle to the ISEEI device
 *  \param log_callback pointer to function to run for log write, set NULL to use built-in function
 *  \return 0 if successful, otherwise error code.
 */
ISSEILIB_DLL_API uint32_t isseilib_set_log_callback(IN isseilib_handle* handle, isseilib_log_callback log_callback);
#ifdef __cplusplus
}
#endif
#endif // ISSEILIB_H
