/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <sys/un.h>

#include <onyx/culstring.h>
#include <onyx/file.h>
#include <onyx/net/socket.h>
#include <onyx/net/socket_table.h>
#include <onyx/packetbuf.h>
#include <onyx/process.h>

#include <onyx/utility.hpp>

/**
 * @brief Validates a (sockaddr_un, len) pair
 *
 * @param addr Pointer to sockaddr_un
 * @param len Length of sockaddr_un
 * @return True if valid, else false
 */
bool validate_unix_address(const sockaddr_un *addr, socklen_t len)
{
    if (len < sizeof(sa_family_t))
        return false;

    if (addr->sun_family != AF_UNIX)
        return false;

    return true;
}

/**
 * @brief Represents a UNIX domain socket's name
 * Handles both anonymous sockets and filesystem sockets
 *
 */
struct un_name
{
    bool is_fs_sock_;
    union {
        inode *inode_;
        cul::string anon_path_;
    };

    /**
     * @brief Construct an empty un_name
     *
     */
    constexpr un_name() : is_fs_sock_{true}, inode_{}
    {
    }

    /**
     * @brief Construct an anonymous un_name
     *
     * @param anon_path Anonymous name
     */
    un_name(cul::string &&anon_path) : is_fs_sock_{false}, anon_path_{anon_path}
    {
    }

    void release()
    {
        if (is_fs_sock_)
        {
            inode_unref(inode_);
            inode_ = nullptr;
        }
        else
        {
            anon_path_.clear();
        }
    }

    un_name &operator=(un_name &&rhs)
    {
        if (this == &rhs)
            return *this;
        release();
        is_fs_sock_ = rhs.is_fs_sock_;

        if (is_fs_sock_)
        {
            inode_ = rhs.inode_;
            rhs.inode_ = nullptr;
        }
        else
        {
            new (&anon_path_) cul::string{cul::move(rhs.anon_path_)};
        }

        return *this;
    }

    un_name(un_name &&rhs)
    {
        if (this == &rhs)
            return;

        is_fs_sock_ = rhs.is_fs_sock_;

        if (is_fs_sock_)
        {
            inode_ = rhs.inode_;
            rhs.inode_ = nullptr;
        }
        else
        {
            new (&anon_path_) cul::string{cul::move(rhs.anon_path_)};
        }
    }

    CLASS_DISALLOW_COPY(un_name);
    /**
     * @brief Destroy the un_name object, and call the constructors
     *
     */
    ~un_name()
    {
        if (is_fs_sock_)
        {
            if (inode_)
                close_vfs(inode_);
        }
        else
            anon_path_.~basic_string();
    }

    fnv_hash_t hash() const
    {
        if (is_fs_sock_)
        {
            return fnv_hash(&inode_, sizeof(inode_));
        }
        else
        {
            return fnv_hash(anon_path_.c_str(), anon_path_.length());
        }
    }

    bool operator==(const un_name &rhs) const
    {
        if (rhs.is_fs_sock_ != is_fs_sock_)
            return false;
        if (is_fs_sock_)
            return rhs.inode_ == inode_;
        else
            return rhs.anon_path_ == anon_path_;
    }
};

/**
 * @brief Represents a UNIX domain socket
 *
 */
class un_socket : public socket
{
private:
    /**
     * @brief Do autobind of the socket
     *
     * @return 0 on success, -errno on error
     */
    int do_autobind();

    /**
     * @brief Bind the socket to an anonymous address
     *
     * @param anon_address String of the address
     * @return 0 on success, -errno on error
     */
    int do_anon_bind(cul::string anon_address);

    /**
     * @brief Bind on a filesystem socket
     *
     * @param path Path of the UNIX socket
     * @return 0 on success, negative error codes
     */
    int do_fs_bind(cul::string path);

    un_name src_addr_;

    un_socket *dst_{nullptr};

public:
    list_head_cpp<un_socket> bind_table_node{this};
    un_socket(int type, int protocol)
    {
        this->type = type;
        this->proto = protocol;
    }

    ~un_socket() override;

    int getsockopt(int level, int optname, void *optval, socklen_t *optlen) override
    {
        return -ENOPROTOOPT;
    }

    int setsockopt(int level, int optname, const void *optval, socklen_t optlen) override
    {
        return -ENOPROTOOPT;
    }

    int bind(sockaddr *addr, socklen_t addrlen) override;

    void unbind();

    static inline fnv_hash_t make_hash(un_socket *&sock)
    {
        return sock->src_addr_.hash();
    }

    un_name &src_addr()
    {
        return src_addr_;
    }

    void close() override;

    int connect(sockaddr *addr, socklen_t addrlen, int flags) override;
};

class unix_socket_table
{
private:
    cul::hashtable2<un_socket *, CONFIG_SOCKET_HASHTABLE_SIZE, uint32_t, &un_socket::make_hash>
        socket_hashtable;
    struct spinlock lock_[CONFIG_SOCKET_HASHTABLE_SIZE];

public:
    unix_socket_table()
    {
        for (auto &l : lock_)
            spinlock_init(&l);
    }

    ~unix_socket_table() = default;

    CLASS_DISALLOW_MOVE(unix_socket_table);
    CLASS_DISALLOW_COPY(unix_socket_table);

    size_t index_from_hash(fnv_hash_t hash)
    {
        return socket_hashtable.get_hashtable_index(hash);
    }

    void lock(fnv_hash_t hash)
    {
        spin_lock(&lock_[index_from_hash(hash)]);
    }

    void unlock(fnv_hash_t hash)
    {
        spin_unlock(&lock_[index_from_hash(hash)]);
    }

    bool add_socket(un_socket *sock, unsigned int flags)
    {
        bool unlocked = flags & ADD_SOCKET_UNLOCKED;
        auto hash = sock->src_addr().hash();

        if (!unlocked)
            lock(hash);

        socket_hashtable.add_element(sock, sock->bind_table_node.to_list_head());

        if (!unlocked)
            unlock(hash);

        return true;
    }

    bool remove_socket(un_socket *sock, unsigned int flags)
    {
        bool unlocked = flags & REMOVE_SOCKET_UNLOCKED;

        auto hash = sock->src_addr().hash();

        if (!unlocked)
            lock(hash);

        socket_hashtable.remove_element(sock, sock->bind_table_node.to_list_head());

        if (!unlocked)
            unlock(hash);

        return true;
    }

    un_socket *get_socket(const un_name &name, unsigned int flags, unsigned int inst)
    {
        auto hash = name.hash();
        bool unlocked = flags & GET_SOCKET_UNLOCKED;
        auto index = socket_hashtable.get_hashtable_index(hash);

        if (!unlocked)
            lock(hash);

        /* Alright, so this is the standard hashtable thing - hash the socket_id,
         * get the iterators, and then iterate through the list and compare the
         * socket_id with the socket's internal id. This should be pretty efficient.
         * My biggest worry right now is that the hashtables may be too small for a lot of
         * system load. We should do something like linux where its hash tables are allocated
         * dynamically, based on the system memory's size.
         */

        auto list = socket_hashtable.get_hashtable(index);

        un_socket *ret = nullptr;

        list_for_every (list)
        {
            auto sock = list_head_cpp<un_socket>::self_from_list_head(l);

            if (sock->src_addr() == name && inst-- == 0)
            {
                ret = sock;
                break;
            }
        }

        /* GET_SOCKET_CHECK_EXISTENCE is very useful for operations like bind,
         * as to avoid two extra atomic operations.
         */

        if (ret && !(flags & GET_SOCKET_CHECK_EXISTENCE))
            ret->ref();

        if (!unlocked)
            unlock(hash);

        return ret;
    }
};

static unix_socket_table un_sock_table;
/**
 * @brief Bind the socket to an anonymous address
 *
 * @param anon_address String of the address
 * @return 0 on success, -errno on error
 */
int un_socket::do_anon_bind(cul::string anon_address)
{
    src_addr_.is_fs_sock_ = false;
    src_addr_.anon_path_ = cul::move(anon_address);
    auto hash = src_addr_.hash();
    un_sock_table.lock(hash);

    if (un_sock_table.get_socket(src_addr_, GET_SOCKET_UNLOCKED | GET_SOCKET_CHECK_EXISTENCE, 0))
    {
        un_sock_table.unlock(hash);
        return -EADDRINUSE;
    }

    if (!un_sock_table.add_socket(this, ADD_SOCKET_UNLOCKED))
    {
        un_sock_table.unlock(hash);
        return -ENOMEM;
    }

    un_sock_table.unlock(hash);

    bound = true;

    return 0;
}

/**
 * @brief Bind on a filesystem socket
 *
 * @param path Path of the UNIX socket
 * @return 0 on success, negative error codes
 */
int un_socket::do_fs_bind(cul::string path)
{
    const auto perms = 0777 & ~get_current_process()->ctx.umask;
    auto_file curr_dir = get_current_directory();
    auto base = get_fs_base(path.c_str(), curr_dir.get_file());

    auto created = mknod_vfs(path.c_str(), perms | S_IFSOCK, 0, base->f_dentry);

    if (!created)
    {
        int st = -errno;

        if (st == -EEXIST)
            st = -EADDRINUSE;
        return st;
    }

    src_addr_.is_fs_sock_ = true;
    src_addr_.inode_ = created->f_ino;

    // Note: We don't need to check for existance of a socket with the same inode, as we have
    // just created it. The filesystem serves as a kind of a socket table there.

    // Failure seems very unlikely.
    if (!un_sock_table.add_socket(this, 0))
    {
        fd_put(created);
        unlink_vfs(path.c_str(), 0, base);
        src_addr_.inode_ = nullptr;
        return -ENOMEM;
    }

    // Release references to the created fd and the base directory, and reference the inode we
    // have just stored.

    inode_ref(created->f_ino);

    fd_put(created);

    bound = true;

    return 0;
}

/**
 * @brief Do autobind of the socket
 *
 * @return 0 on success, -errno on error
 */
int un_socket::do_autobind()
{
    // unix(7)
    // If a bind(2) call specifies addrlen as sizeof(sa_family_t), or
    // the SO_PASSCRED socket option was specified for a socket that was
    // not explicitly bound to an address, then the socket is autobound
    // to an abstract address.  The address consists of a null byte
    // followed by 5 bytes in the character set [0-9a-f].
    char anon_path[5];
    uint32_t autobind_addr = 0;
    uint32_t max_addr = 0xfffff;

    // TODO: This is slow.

    for (; autobind_addr <= max_addr; autobind_addr++)
    {
        snprintf(anon_path, 5, "%x", autobind_addr);
        if (do_anon_bind(cul::string{anon_path}) == 0)
            return 0;
    }

    return -EADDRINUSE;
}

int un_socket::bind(sockaddr *addr, socklen_t addrlen)
{
    const sockaddr_un *un_addr = (const sockaddr_un *) addr;

    if (!validate_unix_address(un_addr, addrlen))
        return -EINVAL;

    if (addrlen == sizeof(sa_family_t))
    {
        // Autobind requested
        return do_autobind();
    }

    size_t path_len = addrlen - sizeof(sa_family_t);

    if (un_addr->sun_path[0] == '\0')
    {
        // Anonymous bind
        path_len--;

        // Empty path
        if (path_len == 0)
            return -EINVAL;
        cul::string s{&un_addr->sun_path[1], path_len};

        if (!s)
            return -ENOMEM;

        return do_anon_bind(s);
    }

    // Filesystem bind

    cul::string s{un_addr->sun_path, path_len};
    if (!s)
        return -ENOMEM;

    return do_fs_bind(s);
}

void un_socket::unbind()
{
    un_sock_table.remove_socket(this, 0);
}

expected<un_name, int> sockaddr_to_un(sockaddr *addr, socklen_t addrlen)
{
    const sockaddr_un *un_addr = (const sockaddr_un *) addr;

    if (!validate_unix_address(un_addr, addrlen))
        return unexpected{-EINVAL};

    const char *path = un_addr->sun_path;
    size_t path_len = addrlen - sizeof(sa_family_t);

    if (un_addr->sun_path[0] == '\0')
    {
        path_len--;
        path++;
    }

    if (path_len == 0)
        return unexpected{-EINVAL};

    un_name name;

    if (un_addr->sun_path[0] == '\0')
    {
        name.is_fs_sock_ = false;
        name.anon_path_ = cul::string{path, path_len};
        if (!name.anon_path_)
            return unexpected{-ENOMEM};
    }
    else
    {
        name.is_fs_sock_ = true;
        cul::string p{path, path_len};
        if (!p)
            return unexpected{-ENOMEM};

        auto_file cwd = get_current_directory();
        auto_file f = open_vfs(cwd.get_file(), p.c_str());
        if (!f)
            return unexpected{-errno};
        if (!S_ISSOCK(f.get_file()->f_ino->i_mode))
            return unexpected{-ECONNREFUSED};
        name.inode_ = f.get_file()->f_ino;
        inode_ref(name.inode_);
    }

    return cul::move(name);
}

int un_socket::connect(sockaddr *addr, socklen_t addrlen, int flags)
{
    if (listening())
        return -EINVAL;

    if (connected)
        return -EISCONN;

    auto ex = sockaddr_to_un(addr, addrlen);

    if (ex.has_error())
        return ex.error();

    auto peer = un_sock_table.get_socket(ex.value(), 0, 0);
    if (!peer)
        return -ECONNREFUSED;

    if (peer->type != type || (type == SOCK_STREAM && !peer->listening()))
    {
        // Incompatible sockets or the peer isn't listening (when SOCK_STREAM)
        peer->unref();
        return -ECONNREFUSED;
    }

    dst_ = peer;

    return 0;
}

void un_socket::close()
{
    unref();
}

un_socket::~un_socket()
{
    if (bound)
    {
        unbind();
    }

    if (dst_)
        dst_->unref();
}
/**
 * @brief Create a UNIX socket
 *
 * @param type Type of the socket
 * @param protocol Socket's protocol (PROTOCOL_UNIX)
 * @return Pointer to socket object, or nullptr with errno set
 */
socket *unix_create_socket(int type, int protocol)
{
    return new un_socket{type, protocol};
}
