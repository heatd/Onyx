/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#pragma once

#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <system_error>
#include <fstream>
#include <istream>

#include <dhcpcd.hpp>
#include <netctl.hpp>
#include <v6/addrcfg.hpp>

#include <json.hpp>

class sys_error : public std::runtime_error
{
public:
	sys_error(const char *error) : std::runtime_error(std::string(error) + ": " + strerror(errno)) {}
	sys_error(const std::string& error) : std::runtime_error(error + ": " + strerror(errno)) {}
	sys_error(const char *error, int err) : std::runtime_error(std::string(error) + ": " + strerror(err)) {}
	sys_error(const std::string& error, int err) : std::runtime_error(error + ": " + strerror(err)) {}
	~sys_error() = default;
};

using namespace nlohmann;

namespace netctl
{

class instance
{
private:
	int fd;
	std::uint32_t if_index;
	const std::string name;
	std::thread instance_thread;
	std::array<unsigned char, 6> mac;
	json config_file;

public:
	instance(int fd, const std::string& name) : fd{fd}, name{name}, instance_thread(&instance::run, this) {}

	void fetch_mac()
	{
		if(ioctl(fd, SIOGETMAC, mac.data()) < 0)
		{
			throw std::runtime_error(std::string("ioctl: Could not get the local mac address: ") + strerror(errno));
		}

		if(ioctl(fd, SIOGETINDEX, &if_index) < 0)
		{
			throw sys_error("Failed to get the interface index");
		}
	}

	std::string config_file_path() const;

	void create_new_profile(const std::string& cfg);

	void get_configs()
	{
		/* Let's try to read the config */
		const auto config_path = config_file_path();

		/* There's a possibility that the profile doesn't exist; it may be a new network interface, 
		 * the permissions may be screwed up, etc.
		 * If that is the case, we're creating a new profile from scratch, using the default as a
		 * starting point and overwriting whatever may have been there.
		 */
		if(access(config_path.c_str(), R_OK | W_OK) < 0)
		{
			create_new_profile(config_path);
		}

		std::ifstream f(config_path);

		f >> config_file;
	}

	void run()
	{
		/* Let's set up the netif. First, get the mac address, which should
		 * help us out significantly in the future, for IPv6 purposes.
		 */
		fetch_mac();

		get_configs();

		auto new_name = std::string(name);

		dhcpcd::create_instance(new_name);

		netctl::v6::configure_if(*this);
	}

	~instance()
	{
		instance_thread.join();
		close(fd);
	}

	json& get_cfg()
	{
		return config_file;
	}

	const std::array<unsigned char, 6>& get_mac() const
	{
		return mac;
	}

	const std::string& get_name() const
	{
		return name;
	}

	int get_fd() const
	{
		return fd;
	}

	std::uint32_t get_if_index() const
	{
		return if_index;
	}
};

extern int nkfd;

}
