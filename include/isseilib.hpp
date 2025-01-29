/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Intel Corporation
 */

 /*! \file isseilib.hpp
   *  \brief issei access library C++ API
   */

#ifndef ISSEILIB_CPP_WRAPPER_H
#define ISSEILIB_CPP_WRAPPER_H

#include "isseilib.h"
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>


namespace intel {
	namespace security {

		/**
		 * \class issei_error_category
		 * \brief Error category class for ISSEI library errors.
		 */
		class issei_error_category : public std::error_category
		{
		public:
			/**
			* \brief Returns the name of the error category.
			*
			* This function overrides the name() function from std::error_category
			* to provide a custom name for the ISSEI error category.
			*
			* \return A C-string representing the name of the error category.
			*/
			const char* name() const noexcept override
			{
				return "issei_error_category";
			}

			/**
			* \brief Returns a message corresponding to the error value.
			* \param ev The error value.
			* \return A string describing the error.
			*/
			std::string message(int ev) const override
			{
				switch (ev) {
				case ISSEILIB_SUCCESS: return "Success";
				case ISSEILIB_ERROR_GENERAL: return "General error";
				case ISSEILIB_ERROR_SMALL_BUFFER: return "Small buffer";
				case ISSEILIB_ERROR_INVALID_PARAM: return "Invalid parameter";
				case ISSEILIB_ERROR_TIMEOUT: return "Timeout";
				case ISSEILIB_ERROR_PERMISSION_DENIED: return "Permission denied";
				case ISSEILIB_ERROR_DEV_NOT_FOUND: return "Device not found";
				case ISSEILIB_ERROR_DEV_NOT_READY: return "Device not ready";
				case ISSEILIB_ERROR_CLIENT_NOT_FOUND: return "Client not found";
				case ISSEILIB_ERROR_DISCONNECTED: return "Disconnected";
				case ISSEILIB_ERROR_BUSY: return "Busy";
				case ISSEILIB_ERROR_ABORT: return "Abort";
				default: return "Unknown error code: " + std::to_string(ev);
				}
			}
		};

		/**
		* \class issei_exception
		* \brief Exception class for ISSEI library errors.
		*/
		class issei_exception : public std::system_error
		{
		public:
			/**
			* \brief Constructs an issei_exception with the given result code.
			* \param result_code The result code representing the error.
			*/
			explicit issei_exception(uint32_t result_code) :
				std::system_error(static_cast<int>(result_code), issei_error_category())
			{
			}

			/**
			* \brief Gets the result code of the failed operation.
			* \return The result code.
			*/
			uint32_t get_result_code() const noexcept
			{
				return static_cast<uint32_t>(code().value());
			}
		};


		/**
		 * \class issei
		 * \brief Wrapper class for the ISSEI device access library API.
		 */
		class issei {
		public:
			/**
			 * \brief Constructor for the Issei class.
			 * \param device The device address.
			 * \param log_level The log level (default: ISSEILIB_LOG_LEVEL_ERROR).
			 * \param log_callback The log callback function (default: nullptr).
			 * \throws std::runtime_error if failed to initialize ISSEI connection.
			 */
			issei(const isseilib_device_address& device, uint32_t log_level = ISSEILIB_LOG_LEVEL_ERROR, isseilib_log_callback log_callback = nullptr)
			{
				auto result_code = isseilib_init(&handle_, device, log_level, log_callback);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
			}

			/**
			 * \brief Constructor for the Issei class.
			 * \param log_level The log level (default: ISSEILIB_LOG_LEVEL_ERROR).
			 * \param log_callback The log callback function (default: nullptr).
			 * \throws std::runtime_error if failed to initialize ISSEI connection.
			 */
			issei(uint32_t log_level = ISSEILIB_LOG_LEVEL_ERROR, isseilib_log_callback log_callback = nullptr) :
				issei({ isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE , nullptr }, log_level, log_callback)
			{

			}

			/**
			 * \brief Constructor for the Issei class.
			 * \param device The device address.
			 * \param log_level The log level (default: ISSEILIB_LOG_LEVEL_ERROR).
			 * \param log_callback The log callback function (default: nullptr).
			 * \throws std::runtime_error if failed to initialize ISSEI connection.
			 */
			issei(const ISSEILIB_DEVICE_HANDLE device_handle, uint32_t log_level = ISSEILIB_LOG_LEVEL_ERROR, isseilib_log_callback log_callback = nullptr) :
				issei({ isseilib_device_address::ISSEILIB_DEVICE_TYPE_HANDLE, {.handle = device_handle} }, log_level, log_callback)
			{
			}

			/**
			* \brief Move constructor for the issei class.
			*
			* This constructor transfers ownership of the internal handle from the source object to the target object.
			* The source object is left in a valid but unspecified state.
			*
			* \param other The source object to move from.
			*/
			issei(issei&& other) noexcept : handle_(other.handle_)
			{
				other.handle_ = nullptr;
			}

			/**
			 * \brief Destructor for the Issei class.
			 */
			~issei()
			{
				isseilib_deinit(&handle_);
			}

			/**
			 * \brief Delete copy constructor
			 */
			issei(const issei&) = delete;

			/**
			 * \brief Delete copy assignment operator
			 */
			issei& operator=(const issei&) = delete;

			/**
			* \brief Move assignment operator for the issei class.
			*
			* This operator transfers ownership of the internal handle from the source object to the target object.
			* The source object is left in a valid but unspecified state.
			*
			* \param other The source object to move from.
			* \return A reference to the target object.
			*/
			issei& operator=(issei&& other) noexcept
			{
				if (this != &other) {
					isseilib_deinit(&handle_);
					handle_ = other.handle_;
					other.handle_ = nullptr;
				}
				return *this;
			}

			/**
			 * \brief Connects to the ISSEI Client
			 * \param uuid The UUID of the firmware client to connect to.
			 * \return The client properties.
			 * \throws issei_exception if the operation fails.
			 */
			isseilib_client_properties connect(const ISSEILIB_UUID& uuid)
			{
				isseilib_client_properties client_properties;
				std::copy(uuid, uuid + sizeof(ISSEILIB_UUID), client_properties.uuid);

				uint32_t result_code = isseilib_connect(&handle_, &client_properties);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}

				client_prop_ = client_properties;
				return client_properties;
			}

			/**
			 * \brief Disconnects from the ISSEI device.
			 * \throws issei_exception if the operation fails.
			 */
			void disconnect()
			{
				client_prop_.reset();

				uint32_t result_code = isseilib_disconnect(&handle_);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
			}

			/**
			 * \brief Writes data to the ISSEI device.
			 * \param data The data to write.
			 * \param timeout The timeout value (default: 0).
			 * \throws issei_exception if the operation fails.
			 */
			void write(const std::span<uint8_t>& data, uint32_t timeout = 0)
			{
				uint32_t result_code = isseilib_write(&handle_, data.data(), data.size(), timeout);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
			}

			/**
			 * \brief Reads data from the ISSEI device.
			 * \param timeout The timeout value (default: 0).
			 * \return vector of bytes of the read data.
			 * \throws issei_exception if the operation fails.
			 */
			std::vector<uint8_t> read(uint32_t timeout = 0)
			{

				if (!client_prop_.has_value()) {
					throw issei_exception(ISSEILIB_ERROR_DISCONNECTED);
				}

				std::vector<uint8_t> data(client_prop_->max_message_size);

				size_t data_size = data.size();
				uint32_t result_code = isseilib_read(&handle_, data.data(), &data_size, timeout);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}

				// Resize vector from max_message_size to actual data size
				data.resize(data_size);

				return move(data);
			}

			/**
			 * \brief Gets the status of the ISSEI device.
			 * \return The driver status.
			 * \throws issei_exception if the operation fails.
			 */
			uint32_t get_status()
			{
				uint32_t driver_status = 0;
				uint32_t result_code = isseilib_get_status(&handle_, &driver_status);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
				return driver_status;
			}

			const size_t KIND_DEFAULT_SIZE = 128;
			/**
			 * \brief Gets the kind of the ISSEI device.
			 * \return The kind of the ISSEI device.
			 * \throws issei_exception if the operation fails.
			 */
			std::string get_kind()
			{
				std::string kind(KIND_DEFAULT_SIZE, 0);

				size_t kind_size = KIND_DEFAULT_SIZE;
				uint32_t result_code = isseilib_get_kind(&handle_, kind.data(), &kind_size);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
				return kind;
			}

			/**
			 * \brief Gets the firmware version of the ISSEI device.
			 * \return The firmware version of the ISSEI device.
			 * \throws issei_exception if the operation fails.
			 */
			isseilib_device_fw_version get_fw_version()
			{
				isseilib_device_fw_version fw_version;
				uint32_t result_code = isseilib_get_fw_version(&handle_, &fw_version);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
				return fw_version;
			}

			/**
			 * \brief Gets the firmware status of the ISSEI device.
			 * \param register_number The register number.
			 * \return The firmware status of the ISSEI device.
			 * \throws issei_exception if the operation fails.
			 */
			uint32_t get_fw_status(uint8_t register_number)
			{
				uint32_t fw_status;
				uint32_t result_code = isseilib_get_fw_status(&handle_, register_number, &fw_status);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
				return fw_status;
			}

			/**
			 * \brief Gets the list of connected clients.
			 * \return The list of connected clients.
			 * \throws issei_exception if the operation fails.
			 */
			std::vector<isseilib_client_properties> get_client_list()
			{
				size_t num_clients = 0;
				uint32_t result_code = isseilib_get_client_list(&handle_, nullptr, &num_clients);
				if (result_code != ISSEILIB_SUCCESS && result_code != ISSEILIB_ERROR_SMALL_BUFFER) {
					throw issei_exception(result_code);
				}

				std::vector<isseilib_client_properties> client_list(num_clients);
				result_code = isseilib_get_client_list(&handle_, client_list.data(), &num_clients);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}

				return std::move(client_list);
			}

			/**
			 * \brief Checks if a client with the given UUID exists.
			 * \param client_uuid The client UUID.
			 * \return True if the client exists, false otherwise.
			 * \throws issei_exception if the operation fails.
			 */
			bool is_client_exists(const ISSEILIB_UUID client_uuid)
			{
				bool exists;
				uint32_t result_code = isseilib_is_client_exists(&handle_, client_uuid, &exists);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
				return exists;
			}

			/**
			 * \brief Sets the log level of the ISSEI device library.
			 * \param log_level The log level.
			 * \throws issei_exception if the operation fails.
			 */
			void set_log_level(uint32_t log_level)
			{
				uint32_t result_code = isseilib_set_log_level(&handle_, log_level);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
			}

			/**
			 * \brief Gets the log level of the ISSEI device library.
			 * \param log_level The log level.
			 * \throws issei_exception if the operation fails.
			 */
			void get_log_level(uint32_t& log_level)
			{
				uint32_t result_code = isseilib_get_log_level(&handle_, &log_level);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
			}

			/**
			 * \brief Sets the log callback function of the ISSEI device library.
			 * \param log_callback The log callback function.
			 * \throws issei_exception if the operation fails.
			 */
			void set_log_callback(isseilib_log_callback log_callback)
			{
				uint32_t result_code = isseilib_set_log_callback(&handle_, log_callback);
				if (result_code != ISSEILIB_SUCCESS) {
					throw issei_exception(result_code);
				}
			}

		private:
			isseilib_handle handle_;
			std::optional<isseilib_client_properties> client_prop_;
		};

	} // namespace security
} // namespace intel

#endif //ISSEILIB_CPP_WRAPPER_H