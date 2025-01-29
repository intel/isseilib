/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2025 Intel Corporation */

#include <thread>

#include "isseilib.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "isseilib.h"
#include "isseilib.hpp"


using ::testing::_;
using ::testing::Return;


TEST(cpp_basic, isseilib_cpp_init_null_handle_fail)
{
	try
	{
		isseilib_device_address addr = {
			.type = isseilib_device_address::ISSEILIB_DEVICE_TYPE_HANDLE,
			.data = {.handle = ISSEILIB_INVALID_DEVICE_HANDLE}
		};

		// Create ISSEI Device
		intel::security::issei device(addr, ISSEILIB_LOG_LEVEL_VERBOSE);

		FAIL();
	}
	catch (const intel::security::issei_exception& ex)
	{
		EXPECT_EQ(ex.code().value(), ISSEILIB_ERROR_INVALID_PARAM);
	}
}

TEST(cpp_basic, isseilib_cpp_init_null_device_handle_fail)
{
	try
	{
		// Create ISSEI Device
		intel::security::issei device(ISSEILIB_INVALID_DEVICE_HANDLE, ISSEILIB_LOG_LEVEL_VERBOSE);

		FAIL();
	}
	catch (const intel::security::issei_exception& ex)
	{
		EXPECT_EQ(ex.code().value(), ISSEILIB_ERROR_INVALID_PARAM);
	}
}

TEST(cpp_basic, isseilib_cpp_get_client_list)
{
	std::vector<isseilib_client_properties> clients;
	EXPECT_NO_THROW({
		intel::security::issei device(ISSEILIB_LOG_LEVEL_VERBOSE);

		clients = device.get_client_list();

		// Check if we have at least one client. 
		EXPECT_GE(clients.size(), 1);
		});
}

TEST(cpp_basic, isseilib_cpp_default_constructor_and_destructor)
{
	EXPECT_NO_THROW({
		intel::security::issei device;
		});
}

TEST(cpp_basic, isseilib_cpp_get_fw_version)
{
	EXPECT_NO_THROW({
			intel::security::issei device(ISSEILIB_LOG_LEVEL_VERBOSE);
			auto fw_version = device.get_fw_version();

			EXPECT_NE(fw_version.major, 0);

		});
}

TEST(cpp_basic, isseilib_cpp_move_semantics)
{
	EXPECT_NO_THROW({
			intel::security::issei device(ISSEILIB_LOG_LEVEL_VERBOSE);

			auto device2 = std::move(device);

			auto fw_version = device2.get_fw_version();

			EXPECT_NE(fw_version.major, 0);

		});
}