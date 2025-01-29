/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2023-2024 Intel Corporation */

#include <thread>
#include "gtest/gtest.h"
#include "isseilib.h"

static inline void COPY_UUID(ISSEILIB_UUID dst, const ISSEILIB_UUID src)
{
	memcpy(dst, src, sizeof(ISSEILIB_UUID));
}

TEST(basic, isseilib_init_deinit_ok)
{
	isseilib_handle handle;
	uint32_t ret;

	ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_SUCCESS);
	isseilib_deinit(&handle);
}

TEST(basic, isseilib_init_deinit_255_ok)
{
#define COUNT 255
	isseilib_handle handle[COUNT];
	uint32_t ret;

	for (size_t i = 0; i < COUNT; i++)
	{
		ret = isseilib_init(&handle[i], { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL },
			ISSEILIB_LOG_LEVEL_ERROR, NULL);
		EXPECT_EQ(ret, ISSEILIB_SUCCESS);
	}
	for (size_t i = 0; i < COUNT; i++)
	{
		isseilib_deinit(&handle[i]);
	}
}

TEST(basic, isseilib_init_null_handle_fail)
{
	uint32_t ret;

	ret = isseilib_init(NULL, {isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL},
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
}

TEST(basic, isseilib_init_device_not_null_fail)
{
	isseilib_handle handle;
	uint32_t ret;

	ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, "test" },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
}

TEST(basic, isseilib_init_device_bad_fail)
{
	isseilib_handle handle;
	char path[] = "NoOneHere";
	char path_long[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
	uint32_t ret;

	ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_PATH, NULL },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
	ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_PATH, path },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_DEV_NOT_FOUND);
	ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_PATH, path_long },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_DEV_NOT_FOUND);
}

TEST(basic, isseilib_init_handle_bad_fail)
{
	struct isseilib_device_address addr;
	isseilib_handle handle;
	uint32_t ret;
	addr.type = isseilib_device_address::ISSEILIB_DEVICE_TYPE_HANDLE;
	addr.data.handle = ISSEILIB_INVALID_DEVICE_HANDLE;

	ret = isseilib_init(&handle, addr, ISSEILIB_LOG_LEVEL_ERROR, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
}

TEST(basic, isseilib_deinit_null_fail)
{
	isseilib_deinit(NULL);
}

class isseilib_inited_test : public ::testing::Test {
protected:
	isseilib_inited_test() {}
	void SetUp() override
	{
		uint32_t ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL },
			ISSEILIB_LOG_LEVEL_ERROR, NULL);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);

		get_first_client();
	}

	void TearDown() override
	{
		isseilib_deinit(&handle);
	}
	
	isseilib_handle handle;
	struct isseilib_client_properties client_property;

	void get_first_client()
	{
		struct isseilib_client_properties* client_properties;
		size_t num_clients = 0;
		int ret;

		ret = isseilib_get_client_list(&handle, NULL, &num_clients);
		if (ret != ISSEILIB_SUCCESS && ret != ISSEILIB_ERROR_SMALL_BUFFER)
		{
			GTEST_SKIP() << "isseilib_get_client_list failed " << ret;
		}
		if (num_clients == 0)
		{
			GTEST_SKIP() << "No clients";
		}

		client_properties = new isseilib_client_properties[num_clients];
		ret = isseilib_get_client_list(&handle, client_properties, &num_clients);
		if (ret != ISSEILIB_SUCCESS)
		{
			delete[] client_properties;
			GTEST_SKIP() << "isseilib_get_client_list failed" << ret;
		}

		COPY_UUID(client_property.uuid, client_properties[0].uuid);
		delete[] client_properties;
	}
};

DEFINE_ISSEILIB_UUID(HECI_TEST0_GUID, 0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_ISSEILIB_UUID(HECI_TEST1_GUID, 0x11111111, 0x1111, 0x1111, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11);
DEFINE_ISSEILIB_UUID(HECI_TEST4_GUID, 0x44444444, 0x4444, 0x4444, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44);

TEST_F(isseilib_inited_test, isseilib_connect_disconnect_test4_ok)
{
	struct isseilib_client_properties client_properties;
	bool exists = false;
	uint32_t ret;

	ret = isseilib_is_client_exists(&handle, HECI_TEST4_GUID, &exists);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	if (!exists)
	{
		GTEST_SKIP() << "No TEST4 client";
	}

	COPY_UUID(client_properties.uuid, HECI_TEST4_GUID);
	ret = isseilib_connect(&handle, &client_properties);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	EXPECT_EQ(client_properties.max_message_size, 5120);
	EXPECT_EQ(client_properties.protocol_version, 1);
	EXPECT_EQ(client_properties.flags, 0);

	ret = isseilib_disconnect(&handle);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
}

TEST_F(isseilib_inited_test, isseilib_connect_disconnect_any_ok)
{
	uint32_t ret;

	ret = isseilib_connect(&handle, &client_property);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_disconnect(&handle);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
}

TEST_F(isseilib_inited_test, isseilib_connect_disconnect_twice_ok)
{
	uint32_t ret;

	ret = isseilib_connect(&handle, &client_property);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_disconnect(&handle);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	/* second connect after disconnect on the same handle */
	ret = isseilib_connect(&handle, &client_property);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_disconnect(&handle);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
}

TEST_F(isseilib_inited_test, isseilib_connect_bad_fail)
{
	struct isseilib_client_properties client_properties;
	uint32_t ret;

	COPY_UUID(client_properties.uuid, HECI_TEST0_GUID);
	ret = isseilib_connect(&handle, &client_properties);
	ASSERT_EQ(ret, ISSEILIB_ERROR_CLIENT_NOT_FOUND);
}

TEST_F(isseilib_inited_test, isseilib_connect_null_fail)
{
	struct isseilib_client_properties client_properties;
	uint32_t ret;

	COPY_UUID(client_properties.uuid, HECI_TEST4_GUID);
	ret = isseilib_connect(NULL, &client_properties);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
	ret = isseilib_connect(&handle, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
	ret = isseilib_connect(NULL, NULL);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
}

TEST_F(isseilib_inited_test, isseilib_connect_twice_fail)
{
	uint32_t ret;

	ret = isseilib_connect(&handle, &client_property);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	ret = isseilib_connect(&handle, &client_property);
	EXPECT_EQ(ret, ISSEILIB_ERROR_BUSY);

	ret = isseilib_disconnect(&handle);
	EXPECT_EQ(ret, ISSEILIB_SUCCESS);
}

TEST_F(isseilib_inited_test, isseilib_disconnect_not_connected_ok)
{
	uint32_t ret;

	ret = isseilib_disconnect(&handle);
	EXPECT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_connect(&handle, &client_property);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_disconnect(&handle);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_disconnect(&handle);
	EXPECT_EQ(ret, ISSEILIB_SUCCESS);
}

TEST_F(isseilib_inited_test, isseilib_is_client_exists_ok)
{
	uint32_t ret;
	bool exists;

	ret = isseilib_is_client_exists(&handle, client_property.uuid, &exists);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	ASSERT_EQ(exists, true);
}

TEST_F(isseilib_inited_test, interrupted_read_fail)
{
	std::thread thr;
	isseilib_handle *handle1 = &handle;
	uint32_t ret;

	ret = isseilib_connect(&handle, &client_property);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	thr = std::thread([handle1]() {
		uint8_t buf[256] = { 1 };
		size_t buf_size = sizeof(buf);

		EXPECT_EQ(ISSEILIB_ERROR_ABORT, isseilib_read(handle1, buf, &buf_size, 10000));
	});
	std::this_thread::sleep_for(std::chrono::seconds(1));

	ret = isseilib_disconnect(&handle);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	thr.join();
}

class isseilib_connected_test : public ::testing::Test {
protected:
	isseilib_connected_test() {}
	void SetUp() override
	{
		struct isseilib_client_properties client_properties;
		bool exists = 0;
		uint32_t ret;

		ret = isseilib_init(&handle, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL },
			ISSEILIB_LOG_LEVEL_ERROR, NULL);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);

		ret = isseilib_is_client_exists(&handle, HECI_TEST4_GUID, &exists);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);
		if (!exists)
		{
			GTEST_SKIP() << "No TEST4 client";
		}

		COPY_UUID(client_properties.uuid, HECI_TEST4_GUID);
		ret = isseilib_connect(&handle, &client_properties);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	}
	void TearDown() override
	{
		uint32_t ret;

		ret = isseilib_disconnect(&handle);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);

		isseilib_deinit(&handle);
	}

	isseilib_handle handle;
};

TEST_F(isseilib_connected_test, isseilib_write_read_10_ok)
{
	uint32_t ret;
	uint8_t data[100];
	const size_t data_size = sizeof(data);
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);

	for (size_t i = 0; i < data_size; ++i)
	{
		data[i] = i;
	}

	for (unsigned int i = 0; i < 10; i++)
	{
		data[4] = i;
		ret = isseilib_write(&handle, data, data_size, 5000);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);

		ret = isseilib_read(&handle, buf, &buf_size, 10000);
		ASSERT_EQ(ret, ISSEILIB_SUCCESS);
		EXPECT_EQ(buf_size, data_size);
		for (size_t i = 4; i < data_size; ++i)
		{
			EXPECT_EQ(data[i], buf[i]) << "Buffers differ at index " << i;
		}
	}
}

TEST_F(isseilib_connected_test, isseilib_write_ok)
{
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25 };
	size_t data_size = sizeof(data);

	ret = isseilib_write(&handle, data, data_size, 5000);
	EXPECT_EQ(ret, ISSEILIB_SUCCESS);
}

TEST_F(isseilib_connected_test, isseilib_write_big_fail)
{
	uint32_t ret;
	uint8_t data[6000] = { 0 };
	size_t data_size = sizeof(data);

	ret = isseilib_write(&handle, data, data_size, 5000);
	EXPECT_EQ(ret, ISSEILIB_ERROR_INVALID_PARAM);
}

TEST_F(isseilib_connected_test, isseilib_read_timeout_fail)
{
	uint32_t ret;
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);

	ret = isseilib_read(&handle, buf, &buf_size, 500);
	EXPECT_EQ(ret, ISSEILIB_ERROR_TIMEOUT);

	ret = isseilib_read(&handle, buf, &buf_size, 500);
	EXPECT_EQ(ret, ISSEILIB_ERROR_TIMEOUT);
}

TEST_F(isseilib_connected_test, write_read_small_fail)
{
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25 };
	size_t data_size = sizeof(data);
	uint8_t buf[2] = { 1 };
	size_t buf_size = sizeof(buf);

	ret = isseilib_write(&handle, data, data_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	EXPECT_EQ(ret, ISSEILIB_ERROR_SMALL_BUFFER);
}

TEST_F(isseilib_connected_test, read_timeout_write_read_ok)
{
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25 };
	size_t data_size = sizeof(data);
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);

	ret = isseilib_read(&handle, buf, &buf_size, 500);
	ASSERT_EQ(ret, ISSEILIB_ERROR_TIMEOUT);

	ret = isseilib_write(&handle, data, data_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	EXPECT_EQ(buf_size, data_size);
}

TEST_F(isseilib_connected_test, write_read_read_timeout_fail)
{
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25 };
	size_t data_size = sizeof(data);
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);

	ret = isseilib_write(&handle, data, data_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	EXPECT_EQ(buf_size, data_size);

	ret = isseilib_read(&handle, buf, &buf_size, 500);
	ASSERT_EQ(ret, ISSEILIB_ERROR_TIMEOUT);
}

TEST_F(isseilib_connected_test, write_write_read_read_ok)
{
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26 };
	size_t data_size = sizeof(data);
	uint8_t data1[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
	size_t data1_size = sizeof(data);
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);
	struct isseilib_client_properties client_properties;
	isseilib_handle handle1;

	ret = isseilib_init(&handle1, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	COPY_UUID(client_properties.uuid, HECI_TEST1_GUID);
	ret = isseilib_connect(&handle1, &client_properties);
	EXPECT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_write(&handle, data, data_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_write(&handle1, data1, data1_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	EXPECT_EQ(buf_size, data_size);
	EXPECT_EQ(buf[4], data[4]);

	ret = isseilib_read(&handle1, buf, &buf_size, 10000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);
	EXPECT_EQ(buf_size, data1_size);
	EXPECT_EQ(buf[4], data1[4]);

	isseilib_deinit(&handle1);
}

TEST_F(isseilib_connected_test, write_write_read_fail)
{
	uint32_t ret;
	uint8_t data[] = { 0x21, 0x22, 0x23, 0x24, 0x25 };
	size_t data_size = sizeof(data);
	uint8_t buf[256] = { 1 };
	size_t buf_size = sizeof(buf);

	ret = isseilib_write(&handle, data, data_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	ret = isseilib_write(&handle, data, data_size, 5000);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	ret = isseilib_read(&handle, buf, &buf_size, 10000);
	ASSERT_EQ(ret, ISSEILIB_ERROR_DISCONNECTED);
}

TEST_F(isseilib_connected_test, connect_twice_new_handle_fail)
{
	struct isseilib_client_properties client_properties;
	isseilib_handle handle1;
	uint32_t ret;

	ret = isseilib_init(&handle1, { isseilib_device_address::ISSEILIB_DEVICE_TYPE_NONE, NULL },
		ISSEILIB_LOG_LEVEL_ERROR, NULL);
	ASSERT_EQ(ret, ISSEILIB_SUCCESS);

	COPY_UUID(client_properties.uuid, HECI_TEST4_GUID);
	ret = isseilib_connect(&handle1, &client_properties);
	EXPECT_EQ(ret, ISSEILIB_ERROR_BUSY);

	isseilib_deinit(&handle1);
}

int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
