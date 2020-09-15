/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <fcntl.h>
#include <string.h>

#include <onyx/public/netkernel.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <system_error>
#include <fstream>
#include <istream>

#include "dhcpcd.hpp"

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

const std::string config_files_path = "/etc/netctl/";
const char *default_config_path = "/etc/netctl/default-profile.json";

class instance
{
private:
	int fd;
	const std::string name;
	std::thread instance_thread;
	std::array<unsigned char, 6> mac;
	json config_file;

public:
	instance(int fd, const std::string& name) : fd{fd}, name{name}, instance_thread(&instance::run, this) {}

	void get_mac()
	{
		if(ioctl(fd, SIOGETMAC, mac.data()) < 0)
		{
			throw std::runtime_error(std::string("ioctl: Could not get the local mac address: ") + strerror(errno));
		}
	}

	std::string config_file_path() const
	{
		auto last_name_index = name.rfind("/");
		auto last_name = name.substr(last_name_index + 1);

		return config_files_path + last_name + ".json";
	}

	void create_new_profile(const std::string& cfg)
	{
		int default_fd = open(default_config_path, O_RDONLY | O_CLOEXEC);
		if(default_fd < 0)
		{
			throw sys_error("Error opening the default config");
		}

		/* The new profile's perms are 644: Owner RW, Other R, Group R */
		static constexpr unsigned int new_perms = S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP;

		int newfd = open(cfg.c_str(), O_RDWR | O_CREAT | O_TRUNC, new_perms);
		if(newfd < 0)
		{
			close(default_fd);
			throw sys_error("Error creating a new profile " + cfg);
		}

		char buffer[4096];

		ssize_t st = 0;

		while((st = read(default_fd, buffer, sizeof(buffer))) != 0)
		{
			if(st < 0)
			{
				if(errno == EINTR)
					continue;

				int err = errno;
				close(default_fd);
				unlink(cfg.c_str());
				close(newfd);
				throw sys_error("Error reading from the default fd", err);
			}

			st = write(newfd, buffer, st);

			if(st < 0)
			{
				int err = errno;
				close(default_fd);
				unlink(cfg.c_str());
				close(newfd);
				throw sys_error("Error writing the new profile", err);
			}
		}

		/* Fsync it to make sure it's written, as it's an important config file */

		fsync(newfd);

		close(default_fd);
		close(newfd);
	}

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
		get_mac();

		get_configs();

		auto new_name = std::string(name);

		dhcpcd::create_instance(new_name);
	}

	~instance()
	{
		instance_thread.join();
		close(fd);
	}
};

std::vector<std::unique_ptr<instance>> instances;

void create_instance(const std::string& name)
{
	int fd = open(name.c_str(), O_RDWR);
	if(fd < 0)
	{
		auto error = strerror(errno);

		throw std::runtime_error("Failed to open " + name + ": " + error);
	}

	auto inst = std::make_unique<instance>(fd, name);

	instances.push_back(std::move(inst));
}

}

int main(int argc, char **argv, char **envp)
{
	int logfd = open("/dev/null", O_RDWR);
	if(logfd < 0)
	{
		perror("could not create logfd");
		return 1;
	}

#if 0
	dup2(logfd, 0);
	dup2(logfd, 1);
	dup2(logfd, 2);
#endif

	close(logfd);

	dhcpcd::nkfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
	if(dhcpcd::nkfd < 0)
	{
		perror("nksocket");
		return 1;
	}

	dhcpcd::rtfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
	if(dhcpcd::rtfd < 0)
	{
		perror("nksocket");
		return 1;
	}

	sockaddr_nk nksa;
	nksa.nk_family = AF_NETKERNEL;
	strcpy(nksa.path, "ipv4.rt");
	if(connect(dhcpcd::rtfd, (const sockaddr *) &nksa, sizeof(nksa)) < 0)
	{
		perror("nkconnect");
		return 1;
	}

	printf("%s: Daemon initialized\n", argv[0]);

	/* TODO: Discover NICs in /dev (maybe using netlink? or sysfs) */
	
	std::string name{"/dev/eth0"};
	dhcpcd::init_entropy();

	netctl::create_instance(name);

	while(1)
		sleep(100000);
	return 0;
}
