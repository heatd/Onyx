/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <sys/un.h>

#include <onyx/culstring.h>
#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/iovec_iter.h>
#include <onyx/kunit.h>
#include <onyx/net/socket.h>
#include <onyx/net/socket_table.h>
#include <onyx/packetbuf.h>
#include <onyx/poll.h>
#include <onyx/process.h>

#include <onyx/utility.hpp>

#ifdef CONFIG_KUNIT
#define KUNIT_PUBLIC public:
#else
#define KUNIT_PUBLIC private:
#endif

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
        dentry *dentry_;
        cul::string anon_path_;
    };

    /**
     * @brief Construct an empty un_name
     *
     */
    constexpr un_name() : is_fs_sock_{true}, dentry_{}
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

    /**
     * @brief Create a copy of this un_name
     *
     * @return New un_name, or negative error code
     */
    expected<un_name, int> copy() const
    {
        un_name n;
        n.is_fs_sock_ = is_fs_sock_;
        if (is_fs_sock_)
        {
            n.dentry_ = dentry_;
            dentry_get(dentry_);
        }
        else
        {
            new (&n.anon_path_) cul::string{anon_path_};
            if (!n.anon_path_)
                return unexpected<int>{-ENOMEM};
        }

        return cul::move(n);
    }

    void release()
    {
        if (is_fs_sock_)
        {
            if (dentry_)
                dentry_put(dentry_);
            dentry_ = nullptr;
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
            dentry_ = rhs.dentry_;
            rhs.dentry_ = nullptr;
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
            dentry_ = rhs.dentry_;
            rhs.dentry_ = nullptr;
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
            if (dentry_)
                dentry_put(dentry_);
        }
        else
            anon_path_.~basic_string();
    }

    fnv_hash_t hash() const
    {
        if (is_fs_sock_)
        {
            return fnv_hash(&dentry_->d_inode, sizeof(inode *));
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
        if (is_anon() && rhs.is_anon())
            return true;
        if (is_fs_sock_)
            return rhs.dentry_->d_inode == dentry_->d_inode;
        else
            return rhs.anon_path_ == anon_path_;
    }

    bool is_anon() const
    {
        return is_fs_sock_ && dentry_ == nullptr;
    }
};

#define UN_CLOSED    0
#define UN_LISTENING 1
#define UN_CONNECTED 2
/**
 * @brief Represents a UNIX domain socket
 *
 */
class un_socket : public socket
{
    KUNIT_PUBLIC
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
    int state{UN_CLOSED};

    list_head connection_queue;
    wait_queue connection_wq;
    wait_queue accept_wq;

    list_head inbuf_list;
    wait_queue inbuf_wq;

    struct connection_req
    {
        un_socket *peer;
        un_socket *server_sock{nullptr}; // To be filled by accept()
        bool dead{false};                // Set if the socket got closed and we're still queued

        bool was_woken_up() const
        {
            return server_sock || dead;
        }

        struct list_head list_node;

        connection_req(un_socket *peer) : peer{peer}
        {
        }
    };

    /**
     * @brief Attempt to connect to this socket
     *
     * @param client Socket who wants to connect
     * @return Peer socket created by accept(), or an error code
     */
    expected<un_socket *, int> connect_to(un_socket *client);

    /**
     * @brief Create a socket for accept(), connected to peer and with the same bind as us.
     *
     * @param peer Socket to connect to
     * @return New socket, or negative error code
     */
    expected<un_socket *, int> create_accept_socket(un_socket *peer);

    ref_guard<un_socket> get_peer_locked()
    {
        scoped_hybrid_lock g{socket_lock, this};
        auto sock = dst_;
        if (sock)
            sock->ref();
        return ref_guard{sock};
    }

    /**
     * @brief Queue incoming data
     *
     * @param msg msghdr
     * @return Length transfered, or negative error codes
     */
    ssize_t queue_data(const struct msghdr *msg);

    bool has_data() const
    {
        return !list_is_empty(&inbuf_list) || shutdown_state & SHUTDOWN_RD || peer_nowr;
    }

    expected<packetbuf *, int> get_data(int flags)
    {
        if (flags & MSG_DONTWAIT && !has_data())
            return unexpected<int>{-EWOULDBLOCK};

        int st = wait_for_event_socklocked_interruptible(&inbuf_wq, has_data());
        if (st < 0)
            return unexpected<int>{st};

        if (list_is_empty(&inbuf_list) && (shutdown_state & SHUTDOWN_RD || peer_nowr))
            return unexpected<int>{-EPIPE};

        auto list_head = list_first_element(&inbuf_list);
        return list_head_cpp<packetbuf>::self_from_list_head(list_head);
    }

    // Peer will not write anymore (SHUTDOWN_WR). Use this to skip looking at the peer
    bool peer_nowr : 1;

    void signal_peer_nowr()
    {
        peer_nowr = true;
        wait_queue_wake_all(&inbuf_wq);
    }

    /**
     * @brief Disconnect/discard our peer. Called from close().
     *
     */
    void disconnect_peer();

public:
    list_head_cpp<un_socket> bind_table_node{this};
    un_socket(int type, int protocol)
    {
        this->type = type;
        this->proto = protocol;
        this->domain = AF_UNIX;
        init_wait_queue_head(&connection_wq);
        init_wait_queue_head(&accept_wq);
        init_wait_queue_head(&inbuf_wq);
        INIT_LIST_HEAD(&inbuf_list);
        INIT_LIST_HEAD(&connection_queue);
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

    int listen() override;

    socket *accept(int flags) override;
    short poll(void *poll_file, short events) override;

    ssize_t sendmsg(const struct msghdr *msg, int flags) override;
    ssize_t recvmsg(struct msghdr *msg, int flags) override;
    int getsockname(sockaddr *addr, socklen_t *addrlen) override;
    int getpeername(sockaddr *addr, socklen_t *addrlen) override;

    ssize_t sendmsg_stream(const struct msghdr *msg, int flags);
    ssize_t recvmsg_stream(struct msghdr *msg, int flags);

    ssize_t sendmsg_dgram(const struct msghdr *msg, int flags);
    ssize_t recvmsg_dgram(struct msghdr *msg, int flags);

    static void connect_pair(un_socket *sock0, un_socket *sock1);

    int shutdown(int how) override;
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

    auto ex = mknod_vfs(path.c_str(), perms | S_IFSOCK, 0, base->f_dentry);

    if (ex.has_error())
    {
        int st = ex.error();

        if (st == -EEXIST)
            st = -EADDRINUSE;
        return st;
    }

    src_addr_.is_fs_sock_ = true;
    src_addr_.dentry_ = ex.value();

    // Note: We don't need to check for existance of a socket with the same inode, as we have
    // just created it. The filesystem serves as a kind of a socket table there.

    // Failure seems very unlikely.
    if (!un_sock_table.add_socket(this, 0))
    {
        dentry_put(ex.value());
        unlink_vfs(path.c_str(), 0, base);
        src_addr_.dentry_ = nullptr;
        return -ENOMEM;
    }

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
    bound = false;
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

        auto_file f = open_vfs(AT_FDCWD, p.c_str());
        if (!f)
            return unexpected{-errno};
        if (!S_ISSOCK(f.get_file()->f_ino->i_mode))
            return unexpected{-ECONNREFUSED};
        name.dentry_ = f.get_file()->f_dentry;
        dentry_get(name.dentry_);
    }

    return cul::move(name);
}

short un_socket::poll(void *poll_file, short events)
{
    scoped_hybrid_lock hlock{socket_lock, this};

    short revents = 0;

    if (state == UN_CLOSED)
    {
        return POLLHUP;
    }

    if (state == UN_LISTENING)
    {
        if (events & (POLLIN | POLLRDNORM))
        {
            if (!list_is_empty(&connection_queue))
                revents |= (events & (POLLIN | POLLRDNORM));
            else
                poll_wait_helper(poll_file, &accept_wq);
        }
    }

    if (state == UN_CONNECTED)
    {
        if (events & (POLLIN | POLLRDNORM))
        {
            if (!list_is_empty(&inbuf_list))
                revents |= (events & (POLLIN | POLLRDNORM));
        }

        if (peer_nowr || shutdown_state & SHUTDOWN_RD)
            revents |= POLLHUP;

        if (revents == 0)
        {
            poll_wait_helper(poll_file, &inbuf_wq);
        }
    }

    revents |= POLLOUT;

    return revents & events;
}

/**
 * @brief Attempt to connect to this socket
 *
 * @param client Socket who wants to connect
 * @return Peer socket created by accept(), or an error code
 */
expected<un_socket *, int> un_socket::connect_to(un_socket *client)
{
    scoped_hybrid_lock hlock{socket_lock, this};

    if (state != UN_LISTENING)
        return unexpected<int>{-ECONNREFUSED};

    connection_req r{client};

    list_add_tail(&r.list_node, &connection_queue);
    wait_queue_wake_all(&accept_wq);

    int st = wait_for_event_socklocked_interruptible(&connection_wq, r.was_woken_up());
    if (st < 0)
    {
        list_remove(&r.list_node);
        return unexpected<int>{-EINTR};
    }

    if (r.dead)
        return unexpected<int>{-ECONNREFUSED};

    assert(r.server_sock != nullptr);

    return r.server_sock;
}

int un_socket::connect(sockaddr *addr, socklen_t addrlen, int flags)
{
    if (type == SOCK_STREAM && state != UN_CLOSED)
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

    if (type == SOCK_STREAM)
    {
        // Let's queue ourselves on the peer
        auto expect = peer->connect_to(this);

        if (expect.has_error())
            return expect.error();

        // Unref the "peer" and replace it since we're not actually connecting to it
        peer->unref();
        peer = expect.value();
    }

    connected = true;

    state = UN_CONNECTED;

    dst_ = peer;

    return 0;
}

/**
 * @brief Create a socket for accept(), connected to peer and with the same bind as us.
 *
 * @param peer Socket to connect to
 * @return New socket, or negative error code
 */
expected<un_socket *, int> un_socket::create_accept_socket(un_socket *peer)
{
    ref_guard<un_socket> sock{new un_socket{SOCK_STREAM, PROTOCOL_UNIX}};
    if (!sock)
        return unexpected<int>{-ENOMEM};

    auto ex = this->src_addr_.copy();
    if (ex.has_error())
        return unexpected<int>{ex.error()};

    sock->connect_pair(sock.get(), peer);

    return sock.release();
}

socket *un_socket::accept(int flags)
{
    scoped_hybrid_lock hlock{socket_lock, this};

    if (type != SOCK_STREAM || state != UN_LISTENING)
        return errno = EINVAL, nullptr;

    int st = wait_for_event_socklocked_interruptible(
        &accept_wq, !list_is_empty(&connection_queue) || flags & SOCK_NONBLOCK);

    if (st < 0)
        return errno = -st, nullptr;

    if (list_is_empty(&connection_queue))
    {
        // SOCK_NONBLOCK is implicitly set here
        assert(flags & SOCK_NONBLOCK);
        return errno = EWOULDBLOCK, nullptr;
    }

    auto connreq = container_of(list_first_element(&connection_queue), connection_req, list_node);

    auto ex = create_accept_socket(connreq->peer);

    if (ex.has_error())
        return errno = -ex.error(), nullptr;

    auto acceptsock = ex.value();

    connreq->server_sock = acceptsock;
    // TODO: THUNDER!ing herd
    wait_queue_wake_all(&connection_wq);
    list_remove(&connreq->list_node);

    return acceptsock;
}

/**
 * @brief Disconnect/discard our peer. Called from close().
 *
 */
void un_socket::disconnect_peer()
{
    scoped_hybrid_lock hlock{socket_lock, this};

    if (dst_)
        dst_->unref();
    dst_ = nullptr;
}

void un_socket::close()
{
    if (bound)
    {
        unbind();
    }

    shutdown(SHUTDOWN_RDWR);
    disconnect_peer();
    this->unref();
}

un_socket::~un_socket()
{
    if (bound)
    {
        unbind();
    }

    disconnect_peer();

    // Clear out the pending packets
    list_for_every_safe (&inbuf_list)
    {
        auto pkt = list_head_cpp<packetbuf>::self_from_list_head(l);
        list_remove(&pkt->list_node);
        pkt->unref();
    }
}

int un_socket::listen()
{
    if (type == SOCK_DGRAM)
        return -EINVAL;
    if (!bound)
        return -EINVAL;

    state = UN_LISTENING;

    return 0;
}

static ssize_t fill_pbuf(packetbuf *pbuf, iovec_iter &iter)
{
    ssize_t written = 0;
    while (!iter.empty())
    {
        // XXX Partial writes (in case of failure) must return the written bytes.
        // We don't do that atm, because of partial packetbuf writes that are still kind of
        // buggy.
        auto iovec = iter.curiovec();

        auto st = pbuf->expand_buffer(iovec.iov_base, iovec.iov_len);
        if (st < 0)
            return st;
        else if (st == 0)
            break; // Ran out of room
        iter.advance(st);
        written += st;
    }

    return written;
}

/**
 * @brief Queue incoming data
 *
 * @param msg msghdr
 * @return Length transfered, or negative error codes
 */
ssize_t un_socket::queue_data(const struct msghdr *msg)
{
    bool looked_at_tail = false;
    auto len = iovec_count_length(msg->msg_iov, msg->msg_iovlen);

    if (len < 0)
        return len;

    scoped_hybrid_lock g{socket_lock, this};

    if (shutdown_state & SHUTDOWN_RD)
    {
        // We're shutdown for reading, signal writers with EPIPE
        if (!(flags & MSG_NOSIGNAL))
            kernel_raise_signal(SIGPIPE, get_current_process(), 0, nullptr);
        return -EPIPE;
    }

    iovec_iter iter{{msg->msg_iov, static_cast<size_t>(msg->msg_iovlen)}, static_cast<size_t>(len)};

    while (!iter.empty())
    {
        ref_guard<packetbuf> pbuf;
        if (!looked_at_tail && type == SOCK_STREAM)
        {
            looked_at_tail = true;
            // Attempt to expand the tail packet
            auto l = list_last_element(&inbuf_list);
            if (l)
            {
                packetbuf *tail = list_head_cpp<packetbuf>::self_from_list_head(l);
                if (auto st = fill_pbuf(tail, iter); st < 0)
                    return st;
            }

            continue;
        }

        pbuf = make_refc<packetbuf>();

        if (!pbuf)
            return -ENOBUFS;

        size_t length = cul::min(PACKETBUF_MAX_NR_PAGES << PAGE_SHIFT, iter.bytes);
        if (!pbuf->allocate_space(length))
            return -ENOBUFS;

        if (auto st = fill_pbuf(pbuf.get(), iter); st < 0)
            return st;

        list_add_tail(&pbuf->list_node, &inbuf_list);
        wait_queue_wake_all(&inbuf_wq);
        pbuf.release();
    }

    return len;
}

ssize_t un_socket::sendmsg_stream(const struct msghdr *msg, int flags)
{
    scoped_hybrid_lock g{socket_lock, this};

    if (shutdown_state & SHUTDOWN_WR)
    {
        if (!(flags & MSG_NOSIGNAL))
            kernel_raise_signal(SIGPIPE, get_current_process(), 0, nullptr);
        return -EPIPE;
    }

    if (!connected)
        return -ENOTCONN;

    if (msg->msg_name)
        return -EISCONN;

    CONSUME_SOCK_ERR;

    auto peer = dst_;

    g.unlock();

    return peer->queue_data(msg);
}

ssize_t un_socket::sendmsg_dgram(const struct msghdr *msg, int flags)
{
    scoped_hybrid_lock g{socket_lock, this};

    CONSUME_SOCK_ERR;

    if (shutdown_state & SHUTDOWN_WR)
    {
        if (!(flags & MSG_NOSIGNAL))
            kernel_raise_signal(SIGPIPE, get_current_process(), 0, nullptr);
        return -EPIPE;
    }

    auto peer = dst_;

    if (msg->msg_name)
    {
        auto ex = sockaddr_to_un((sockaddr *) msg->msg_name, msg->msg_namelen);

        if (ex.has_error())
            return ex.error();

        peer = un_sock_table.get_socket(ex.value(), 0, 0);
        if (!peer)
            return -ECONNREFUSED;

        // Must be a dgram socket
        if (peer->type != SOCK_DGRAM)
            return peer->unref(), -EPROTOTYPE;
    }
    else
    {
        if (!peer)
            return -ENOTCONN;

        peer->ref();
    }

    g.unlock();

    auto ret = peer->queue_data(msg);
    peer->unref();
    return ret;
}

ssize_t un_socket::sendmsg(const struct msghdr *msg, int flags)
{
    if (type == SOCK_STREAM)
        return sendmsg_stream(msg, flags);
    return sendmsg_dgram(msg, flags);
}

ssize_t un_socket::recvmsg_stream(struct msghdr *msg, int flags)
{
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    scoped_hybrid_lock g{socket_lock, this};

    CONSUME_SOCK_ERR;

    iovec_iter iter{{msg->msg_iov, static_cast<size_t>(msg->msg_iovlen)},
                    static_cast<size_t>(iovlen)};

    size_t bytes_read = 0;

    auto ex = get_data(flags);

    if (ex.has_error())
    {
        if (ex.error() == -EPIPE)
            return 0;
        return ex.error();
    }

    list_for_every_safe (&inbuf_list)
    {
        if (iter.empty())
            break;
        packetbuf *buf = list_head_cpp<packetbuf>::self_from_list_head(l);
        ssize_t read = buf->copy_iter(iter, flags & MSG_PEEK ? PBF_COPY_ITER_PEEK : 0);

        if (read < 0)
        {
            if (bytes_read == 0)
                bytes_read = read;
            break;
        }

        if (!(flags & MSG_PEEK))
        {
            if (buf->length() == 0)
            {
                list_remove(&buf->list_node);
                buf->unref();
            }
        }

        bytes_read += read;
    }

    msg->msg_controllen = 0;

    return bytes_read;
}

ssize_t un_socket::recvmsg_dgram(struct msghdr *msg, int flags)
{
    // TODO: Merge stream and dgram paths? I'm still not sure...
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    scoped_hybrid_lock g{socket_lock, this};

    CONSUME_SOCK_ERR;

    iovec_iter iter{{msg->msg_iov, static_cast<size_t>(msg->msg_iovlen)},
                    static_cast<size_t>(iovlen)};

    auto ex = get_data(flags);

    if (ex.has_error())
    {
        if (ex.error() == -EPIPE)
            return 0;
        return ex.error();
    }

    packetbuf *buf = ex.value();
    ssize_t read = buf->copy_iter(iter, flags & MSG_PEEK ? PBF_COPY_ITER_PEEK : 0);

    if (read >= 0)
    {
        if (!(flags & MSG_PEEK))
        {
            if (buf->length() == 0)
            {
                list_remove(&buf->list_node);
                buf->unref();
            }
        }
    }

    msg->msg_controllen = 0;

    return read;
}

ssize_t un_socket::recvmsg(struct msghdr *msg, int flags)
{
    if (type == SOCK_STREAM)
        return recvmsg_stream(msg, flags);
    return recvmsg_dgram(msg, flags);
}

int un_get_name(sockaddr_un *addr, socklen_t *addrlen, const un_name &name)
{
    addr->sun_family = AF_UNIX;

    if (name.is_anon())
    {
        // Anonymous socket
        *addrlen = sizeof(sa_family_t);
    }
    else if (name.is_fs_sock_)
    {
        auto filename = dentry_to_file_name(name.dentry_);
        if (!filename)
            return -errno;
        size_t copied = strlcpy(addr->sun_path, filename, sizeof(addr->sun_path));

        auto len = cul::clamp(copied, sizeof(addr->sun_path));

        *addrlen = sizeof(sa_family_t) + len;
        free(filename);
    }
    else
    {
        addr->sun_path[0] = '\0';
        memcpy(&addr->sun_path[1], name.anon_path_.data(), name.anon_path_.length());
        *addrlen = sizeof(sa_family_t) + 1 + name.anon_path_.length();
    }

    return 0;
}

int un_socket::getsockname(sockaddr *addr, socklen_t *addrlen)
{
    scoped_hybrid_lock hlock{socket_lock, this};

    return un_get_name((sockaddr_un *) addr, addrlen, src_addr());
}

int un_socket::getpeername(sockaddr *addr, socklen_t *addrlen)
{
    if (!connected)
        return -ENOTCONN;

    if (shutdown_state & SHUTDOWN_WR)
        return -EINVAL;

    auto peer = get_peer_locked();
    if (!peer)
        return -ENOTCONN;

    // Lock the other socket and inspect its address
    scoped_hybrid_lock hlock2{peer->socket_lock, peer.get()};

    return un_get_name((sockaddr_un *) addr, addrlen, peer->src_addr());
}

int un_socket::shutdown(int how)
{
    scoped_hybrid_lock g{socket_lock, this};

    shutdown_state |= how;
    if (how & SHUTDOWN_RD)
    {
        // We're not reading anymore, wake up readers
        wait_queue_wake_all(&inbuf_wq);
    }

    if (how & SHUTDOWN_WR && type == SOCK_STREAM)
    {
        auto peer = dst_;
        if (peer)
        {
            peer->ref();
            g.unlock();
            peer->signal_peer_nowr();
            peer->unref();
        }
    }

    return 0;
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

void un_socket::connect_pair(un_socket *sock0, un_socket *sock1)
{
    sock0->dst_ = sock1;
    sock1->dst_ = sock0;
    sock0->ref();
    sock1->ref();
    sock0->connected = sock1->connected = true;
    sock0->state = sock1->state = UN_CONNECTED;
}

__always_inline expected<cul::pair<ref_guard<un_socket>, ref_guard<un_socket>>, int>
create_socketpair(int type)
{
    ref_guard<un_socket> sock = make_refc<un_socket>(type, PROTOCOL_UNIX);
    ref_guard<un_socket> sock2 = make_refc<un_socket>(type, PROTOCOL_UNIX);
    if (!sock || !sock2)
        return unexpected{-ENOMEM};

    un_socket::connect_pair(sock.get(), sock2.get());

    return cul::pair<ref_guard<un_socket>, ref_guard<un_socket>>{sock, sock2};
}

expected<cul::pair<ref_guard<socket>, ref_guard<socket>>, int> unix_create_socketpair(int type)
{
    ref_guard<un_socket> sock = make_refc<un_socket>(type, PROTOCOL_UNIX);
    ref_guard<un_socket> sock2 = make_refc<un_socket>(type, PROTOCOL_UNIX);
    if (!sock || !sock2)
        return unexpected{-ENOMEM};

    un_socket::connect_pair(sock.get(), sock2.get());

    return cul::pair<ref_guard<socket>, ref_guard<socket>>{sock.cast<socket>(),
                                                           sock2.cast<socket>()};
}

#ifdef CONFIG_KUNIT

TEST(uipc, socketpair_ok)
{
    auto [sock0, sock1] = create_socketpair(SOCK_DGRAM).unwrap();
    ASSERT_TRUE(sock0->connected);
    ASSERT_TRUE(sock1->connected);
    ASSERT_EQ(sock0.get(), sock1->dst_);
    ASSERT_EQ(sock1.get(), sock0->dst_);
    ASSERT_EQ(UN_CONNECTED, sock0->state);
    ASSERT_EQ(UN_CONNECTED, sock1->state);
}

static ssize_t write(un_socket *socket, cul::slice<u8> data)
{
    auto_addr_limit limit{VM_KERNEL_ADDR_LIMIT};

    msghdr msg;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iovec vec0;
    /* This cast is safe because sendmsg won't write to the iov */
    vec0.iov_base = (void *) data.data();
    vec0.iov_len = data.size_bytes();
    msg.msg_iov = &vec0;
    msg.msg_iovlen = 1;
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;

    return socket->sendmsg(&msg, 0);
}

static ssize_t read(un_socket *socket, cul::slice<u8> expected, unsigned int flags = 0)
{
    auto_addr_limit limit{VM_KERNEL_ADDR_LIMIT};
    u8 tmp[32];

    assert(expected.size_bytes() < sizeof(tmp));
    msghdr msg;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iovec vec0;
    vec0.iov_base = tmp;
    vec0.iov_len = sizeof(tmp);
    msg.msg_iov = &vec0;
    msg.msg_iovlen = 1;
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;

    ssize_t st = socket->recvmsg(&msg, flags);

    if (st < 0)
        return st;

    assert(!memcmp(tmp, expected.data(), expected.size_bytes()));
    return st;
}

template <typename Callable>
bool assert_list(struct list_head *list, Callable c, int wanted_len)
{
    int len = 0;
    list_for_every (list)
    {
        if (!c(l, len))
            return false;
        len++;
    }

    return wanted_len == -1 || len == wanted_len;
}

TEST(uipc, send_dgram_works)
{
    auto [sock0, sock1] = create_socketpair(SOCK_DGRAM).unwrap();

    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));
    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));

    ASSERT_FALSE(list_is_empty(&sock0->inbuf_list));

    ASSERT_TRUE(assert_list(
        &sock0->inbuf_list,
        [&](struct list_head *l, int index) -> bool {
            const packetbuf *buf = list_head_cpp<packetbuf>::self_from_list_head(l);
            return buf->length() == 2 && !memcmp(buf->data, "hi", 2);
        },
        2));
}

TEST(uipc, send_stream_works)
{
    auto [sock0, sock1] = create_socketpair(SOCK_STREAM).unwrap();

    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));
    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));

    ASSERT_FALSE(list_is_empty(&sock0->inbuf_list));

    // Check if SOCK_STREAM properly coalesces messages

    ASSERT_TRUE(assert_list(
        &sock0->inbuf_list,
        [&](struct list_head *l, int index) -> bool {
            const packetbuf *buf = list_head_cpp<packetbuf>::self_from_list_head(l);
            return buf->length() == 4 && !memcmp(buf->data, "hihi", 4);
        },
        1));
}

TEST(uipc, recv_dgram_works)
{
    auto [sock0, sock1] = create_socketpair(SOCK_DGRAM).unwrap();

    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));
    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));

    ASSERT_FALSE(list_is_empty(&sock0->inbuf_list));

    ASSERT_TRUE(assert_list(
        &sock0->inbuf_list,
        [&](struct list_head *l, int index) -> bool {
            const packetbuf *buf = list_head_cpp<packetbuf>::self_from_list_head(l);
            return buf->length() == 2 && !memcmp(buf->data, "hi", 2);
        },
        2));

    ASSERT_EQ(2L, read(sock0.get(), cul::slice<u8>{(u8 *) "hi", 2}));
    ASSERT_EQ(2L, read(sock0.get(), cul::slice<u8>{(u8 *) "hi", 2}));
    ASSERT_EQ(-EWOULDBLOCK, read(sock0.get(), cul::slice<u8>{(u8 *) "", 0}, MSG_DONTWAIT));
}

TEST(uipc, recv_stream_works)
{
    // Make sure SOCK_STREAM recv works and merges two segments into one
    auto [sock0, sock1] = create_socketpair(SOCK_STREAM).unwrap();

    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));
    ASSERT_EQ(2L, write(sock1.get(), cul::slice<u8>{(u8 *) "hi", 2}));

    ASSERT_FALSE(list_is_empty(&sock0->inbuf_list));

    ASSERT_TRUE(assert_list(
        &sock0->inbuf_list,
        [&](struct list_head *l, int index) -> bool {
            const packetbuf *buf = list_head_cpp<packetbuf>::self_from_list_head(l);
            return buf->length() == 4 && !memcmp(buf->data, "hihi", 4);
        },
        1));

    ASSERT_EQ(4L, read(sock0.get(), cul::slice<u8>{(u8 *) "hihi", 4}));
    ASSERT_EQ(-EWOULDBLOCK, read(sock0.get(), cul::slice<u8>{(u8 *) "", 0}, MSG_DONTWAIT));
}

#endif
