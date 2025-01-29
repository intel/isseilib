/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023-2025 Intel Corporation
 */
#include <iostream>
#include <iomanip>
#include "isseilib.hpp"

 
DEFINE_ISSEILIB_UUID(HECI_TEST4_GUID, 0x44444444, 0x4444, 0x4444, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44);
const uint32_t WRITE_TIMEOUT = 5000;
const uint32_t READ_TIMEOUT = 10000;

int main()
{
	std::cout << "C++ Basic Flow" << std::endl;

	try
	{
		// Create ISSEI Device
		intel::security::issei device(ISSEILIB_LOG_LEVEL_QUIET);

		// Connect to TEST Client
		auto client_properties = device.connect(HECI_TEST4_GUID);

		//Print the client properties
		std::cout << "fw client: ver=" << client_properties.protocol_version << " mtu = " << client_properties.max_message_size << " flags = " << client_properties.flags << std::endl;

		// Write Data
		std::vector<uint8_t> data = { 0x21, 0x22, 0x23, 0x24, 0x25 };
		device.write(data, WRITE_TIMEOUT);

		// print the data
		std::cout << "write data: ";
		for (auto& byte : data)
		{
			std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << static_cast<int>(byte) << " ";
		}
		std::cout << std::endl;

		// Read Back the data
		
		auto buf = device.read(READ_TIMEOUT);

		// print the data
		std::cout << "read buf of size " << buf.size() << std::endl;
		std::cout << "read buf: ";
		for (auto& byte : buf)
		{
			std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << static_cast<int>(byte) << " ";
		}
		std::cout << std::endl;

		// Disconnect
		device.disconnect();
	}
	catch (const intel::security::issei_exception& ex)
	{
		std::cerr << "issei Exception: " << ex.what() << std::endl;
	}
	catch (const std::exception& ex)
	{
		std::cerr << "Standard Exception: " << ex.what() << std::endl;
	}
	catch (...)
	{
		std::cerr << "Unknown Exception" << std::endl;
	}
	
	return 0;
}