/*
 * Copyright (c) 2020 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <format>
#include <map>
#include <system_error>
#include <vector>

#include <libmnl/libmnl.h>
#include <uapi/if_addr.h>
#include <uapi/if_link.h>
#include <uapi/netkernel.h>
#include <uapi/rtnetlink.h>

#include <dhcpcd.hpp>
#include <netctl.hpp>
namespace netctl
{

int nkfd;
const std::string config_files_path = "/etc/netctl/";
const char *default_config_path = "/etc/netctl/default-profile.json";

std::vector<std::unique_ptr<instance>> instances;

std::string instance::config_file_path() const
{
    auto last_name_index = name.rfind("/");
    auto last_name = name.substr(last_name_index + 1);

    return config_files_path + last_name + ".json";
}

void instance::create_new_profile(const std::string &cfg)
{
    int default_fd = open(default_config_path, O_RDONLY | O_CLOEXEC);
    if (default_fd < 0)
    {
        throw sys_error("Error opening the default config");
    }

    /* The new profile's perms are 644: Owner RW, Other R, Group R */
    static constexpr unsigned int new_perms = S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP;

    int newfd = open(cfg.c_str(), O_RDWR | O_CREAT | O_TRUNC, new_perms);
    if (newfd < 0)
    {
        close(default_fd);
        throw sys_error("Error creating a new profile " + cfg);
    }

    char buffer[4096];

    ssize_t st = 0;

    while ((st = read(default_fd, buffer, sizeof(buffer))) != 0)
    {
        if (st < 0)
        {
            if (errno == EINTR)
                continue;

            int err = errno;
            close(default_fd);
            unlink(cfg.c_str());
            close(newfd);
            throw sys_error("Error reading from the default fd", err);
        }

        st = write(newfd, buffer, st);

        if (st < 0)
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

void create_instance(const std::string &name)
{
    int fd = open(name.c_str(), O_RDWR);
    if (fd < 0)
    {
        auto error = strerror(errno);

        throw std::runtime_error("Failed to open " + name + ": " + error);
    }

    auto inst = std::make_unique<instance>(fd, name);

    instances.push_back(std::move(inst));
}

} // namespace netctl

static struct mnl_socket *nl_link_sock;

static void start_netlink_listen()
{
    nl_link_sock = mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);
    if (!nl_link_sock)
        throw std::system_error(errno, std::generic_category(), "mnl_socket_open2");
    if (mnl_socket_bind(nl_link_sock, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0)
        throw std::system_error(errno, std::generic_category(), "mnl_socket_bind");
}

class interface
{
    std::string name;
    unsigned int flags;

public:
    interface(std::string name, unsigned int flags) : name{name}, flags{flags}
    {
    }

    const std::string &get_name() const
    {
        return name;
    }

    unsigned int get_flags() const
    {
        return flags;
    }

    void set_flags(unsigned int new_flags)
    {
        flags = new_flags;
    }
};

static std::map<int, interface> iface_map;

static int data_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = (const struct nlattr **) data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
        return MNL_CB_OK;

    switch (type)
    {
        case IFLA_MTU:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
            {
                perror("mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_IFNAME:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
            {
                perror("mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}
static int handle_newlink(const struct nlmsghdr *nlh, void *data)
{
    struct ifinfomsg *ifm = (struct ifinfomsg *) mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    bool start_instance, up;

    /* TODO(pedro): DELLINK */
    if (nlh->nlmsg_type != RTM_NEWLINK)
        return MNL_CB_OK;

    /* If it's a loopback, ignore and don't track it. */
    if (ifm->ifi_flags & IFF_LOOPBACK)
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(*ifm), data_attr_cb, tb);
    auto [it, inserted] = iface_map.try_emplace(
        ifm->ifi_index, interface{mnl_attr_get_str(tb[IFLA_IFNAME]), ifm->ifi_flags});

    up = ifm->ifi_flags & (IFF_UP | IFF_RUNNING);
    auto &interface = it->second;
    start_instance = inserted && up;
    if (!inserted)
    {
        /* Updating an already-tracked interface. If it was down, and now it's up, create the
         * netctl instance as well.
         * TODO(pedro): stop instances and do proper tear-down when the link goes down.
         */
        if (!(interface.get_flags() & (IFF_UP | IFF_RUNNING)) &&
            ifm->ifi_flags & (IFF_UP | IFF_RUNNING))
        {
            interface.set_flags(ifm->ifi_flags);
            std::cout << std::format("netctld: interface {} is now up\n", interface.get_name());
            start_instance = true;
        }
    }
    else
    {
        std::cout << std::format("netctld: found interface {}, {}\n", interface.get_name(),
                                 up ? "up" : "down");
    }

    if (start_instance)
        netctl::create_instance(std::string("/dev/") + interface.get_name());
    return MNL_CB_OK;
}

static void netlink_do_listen()
{
    std::vector<char> buffer;
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;

    unsigned int seq, portid;
    ssize_t ret;

    buffer.resize(MNL_SOCKET_BUFFER_SIZE);

    /* First, send a GETLINK dump request. This + being bound to the LINK RTMGRP makes it so we
     * don't lose messages. */
    nlh = mnl_nlmsg_put_header(buffer.data());
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    ifm = (struct ifinfomsg *) mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifm->ifi_family = AF_UNSPEC;
    portid = mnl_socket_get_portid(nl_link_sock);

    ret = mnl_socket_sendto(nl_link_sock, buffer.data(), nlh->nlmsg_len);
    if (ret < 0)
        throw std::system_error(errno, std::generic_category(), "mnl_socket_sendto(RTM_GETLINK)");
    ret = mnl_socket_recvfrom(nl_link_sock, buffer.data(), MNL_SOCKET_BUFFER_SIZE);
    while (ret > 0)
    {
        ret = mnl_cb_run(buffer.data(), ret, seq, portid, handle_newlink, nullptr);
        if (seq > 0)
        {
            /* We're still looking at the dump. If we get a STOP from it, switch out from the dump
             * data and keep going.
             */
            if (ret == MNL_CB_STOP)
            {
                /* Kernel notifications come with seq = 0 and portid = 0. */
                seq = portid = 0;
            }
        }
        ret = mnl_socket_recvfrom(nl_link_sock, buffer.data(), MNL_SOCKET_BUFFER_SIZE);
    }
}

int main(int argc, char **argv, char **envp)
{
    // Weird argv.
    if (argc == 0)
        return 1;

    /* Force line-buffering for the stdout, in case it was redirected. */
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    netctl::nkfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
    if (netctl::nkfd < 0)
    {
        perror("nksocket");
        return 1;
    }

    dhcpcd::rtfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
    if (dhcpcd::rtfd < 0)
    {
        perror("nksocket");
        return 1;
    }

    sockaddr_nk nksa;
    nksa.nk_family = AF_NETKERNEL;
    strcpy(nksa.path, "ipv4.rt");
    if (connect(dhcpcd::rtfd, (const sockaddr *) &nksa, sizeof(nksa)) < 0)
    {
        perror("nkconnect");
        return 1;
    }

    start_netlink_listen();
    dhcpcd::init_entropy();
    printf("%s: Daemon initialized\n", argv[0]);
    netlink_do_listen();
    return 0;
}
