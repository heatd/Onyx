// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>

#include <uapi/mincore.h>

struct ipc_comm
{
    volatile int cmd;
    volatile uint64_t page;
    volatile unsigned int data;

    static ipc_comm* create();
    void wait_for(int cmd) const
    {
        while (this->cmd != cmd)
            __asm__ __volatile__("" ::: "memory");
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }
};

constexpr unsigned long page_size = 4096;

ipc_comm* ipc_comm::create()
{
    ipc_comm* commbuf = (ipc_comm*) mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (commbuf == MAP_FAILED)
        return nullptr;
    return commbuf;
}

enum class anon_fork_state
{
    NONE = 0,
    CHILD0,
    PARENT0,
    CHILD1,
    PARENT1,
    CHILD2,
    PARENT2
};

#define ASSERT_NE(a, b) assert((a) != (b))
#define ASSERT_EQ(a, b) assert((a) == (b))
#define EXPECT_NE(a, b) ASSERT_NE(a, b)
#define EXPECT_EQ(a, b) ASSERT_EQ(a, b)
#define ASSERT_TRUE(a)  assert(a)
#define EXPECT_TRUE(a)  assert(a)
#define EXPECT_FALSE(a) assert(!(a))

static int mpagemap(void* addr, size_t length, uint64_t* pagemap)
{
    return syscall(SYS_mpagemap, addr, length, pagemap);
}

static void anon_test()
{
    ipc_comm* buf = ipc_comm::create();
    ASSERT_NE(buf, nullptr);
    /* Make sure it's present in the page tables. Not that it shouldn't work if we don't do this,
     * but we're not testing MAP_SHARED at the moment.
     */
    buf->cmd = 0;

    volatile unsigned int* ptr0 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    /* Test if anon memory successfully cows and uncows itself after fork() */
    *ptr0 = 10;

    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Retrieve ptr0's pagemap data */
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        buf->cmd = (int) anon_fork_state::CHILD0;
        buf->wait_for((int) anon_fork_state::PARENT0);
        /* Parent has uncowed themselves, do mpagemap again, and reload the value */
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        buf->cmd = (int) anon_fork_state::CHILD1;
        buf->wait_for((int) anon_fork_state::PARENT1);
        /* uncow ourselves */
        *ptr0 = 0xb00;
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        buf->cmd = (int) anon_fork_state::CHILD2;
        buf->wait_for((int) anon_fork_state::PARENT2);
        _exit(0);
    }
    else
    {
        uint64_t tmp, tmp2;
        /* Parent. Here we actually test things */
        buf->wait_for((int) anon_fork_state::CHILD0);

        /* Check the CoW state */
        mpagemap((void*) ptr0, page_size, &tmp);
        if (buf->page & PAGE_PRESENT)
        {
            EXPECT_EQ(MAPPING_INFO_PADDR(buf->page), MAPPING_INFO_PADDR(tmp));
            EXPECT_FALSE(buf->page & PAGE_WRITABLE);
        }

        EXPECT_FALSE(tmp & PAGE_WRITABLE);
        EXPECT_EQ(*ptr0, 10);
        EXPECT_EQ(buf->data, 10);

        /* now un-CoW the parent's page */
        *ptr0 = 0xbeef;
        mpagemap((void*) ptr0, page_size, &tmp2);
        EXPECT_NE(tmp, tmp2);
        EXPECT_TRUE(tmp2 & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(tmp2));

        /* Tmp now has the current pagemap, tmp2 has the old child's pagemap */
        tmp = tmp2;
        tmp2 = buf->page;
        buf->cmd = (int) anon_fork_state::PARENT0;
        buf->wait_for((int) anon_fork_state::CHILD1);
        ASSERT_TRUE(buf->page & PAGE_PRESENT);
        EXPECT_FALSE(buf->page & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(buf->page));
        EXPECT_EQ(buf->data, 10);
        EXPECT_EQ(*ptr0, 0xbeef);

        buf->cmd = (int) anon_fork_state::PARENT1;
        /* The child will now uncow itself */
        buf->wait_for((int) anon_fork_state::CHILD2);
        ASSERT_TRUE(buf->page & PAGE_PRESENT);
        EXPECT_TRUE(buf->page & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(buf->page));
        EXPECT_EQ(buf->data, 0xb00);
        EXPECT_EQ(*ptr0, 0xbeef);
        buf->cmd = (int) anon_fork_state::PARENT2;
    }
}

static void file_test()
{
    ipc_comm* buf = ipc_comm::create();
    ASSERT_NE(buf, nullptr);
    /* Make sure it's present in the page tables. Not that it shouldn't work if we don't do this,
     * but we're not testing MAP_SHARED at the moment.
     */
    buf->cmd = 0;

    unsigned int fileval;
    int fd = open("/bin/forkcow", O_RDONLY);
    if (fd < 0)
        err(1, "open");

    volatile unsigned int* ptr0 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    fileval = ptr0[1];
    /* Test if anon memory successfully cows and uncows itself after fork() */
    *ptr0 = 10;
    ASSERT_EQ(ptr0[1], fileval);

    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Retrieve ptr0's pagemap data */
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        ASSERT_EQ(ptr0[1], fileval);
        buf->cmd = (int) anon_fork_state::CHILD0;
        buf->wait_for((int) anon_fork_state::PARENT0);
        /* Parent has uncowed themselves, do mpagemap again, and reload the value */
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        ASSERT_EQ(ptr0[1], fileval);
        buf->cmd = (int) anon_fork_state::CHILD1;
        buf->wait_for((int) anon_fork_state::PARENT1);
        /* uncow ourselves */
        *ptr0 = 0xb00;
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        ASSERT_EQ(ptr0[1], fileval);
        buf->cmd = (int) anon_fork_state::CHILD2;
        buf->wait_for((int) anon_fork_state::PARENT2);
        _exit(0);
    }
    else
    {
        uint64_t tmp, tmp2;
        /* Parent. Here we actually test things */
        buf->wait_for((int) anon_fork_state::CHILD0);

        /* Check the CoW state */
        mpagemap((void*) ptr0, page_size, &tmp);
        if (buf->page & PAGE_PRESENT)
        {
            EXPECT_EQ(MAPPING_INFO_PADDR(buf->page), MAPPING_INFO_PADDR(tmp));
            EXPECT_FALSE(buf->page & PAGE_WRITABLE);
        }

        EXPECT_FALSE(tmp & PAGE_WRITABLE);
        EXPECT_EQ(*ptr0, 10);
        EXPECT_EQ(buf->data, 10);
        ASSERT_EQ(ptr0[1], fileval);

        /* now un-CoW the parent's page */
        *ptr0 = 0xbeef;
        mpagemap((void*) ptr0, page_size, &tmp2);
        EXPECT_NE(tmp, tmp2);
        EXPECT_TRUE(tmp2 & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(tmp2));
        ASSERT_EQ(ptr0[1], fileval);

        /* Tmp now has the current pagemap, tmp2 has the old child's pagemap */
        tmp = tmp2;
        tmp2 = buf->page;
        buf->cmd = (int) anon_fork_state::PARENT0;
        buf->wait_for((int) anon_fork_state::CHILD1);
        ASSERT_TRUE(buf->page & PAGE_PRESENT);
        EXPECT_FALSE(buf->page & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(buf->page));
        EXPECT_EQ(buf->data, 10);
        EXPECT_EQ(*ptr0, 0xbeef);

        buf->cmd = (int) anon_fork_state::PARENT1;
        /* The child will now uncow itself */
        buf->wait_for((int) anon_fork_state::CHILD2);
        ASSERT_TRUE(buf->page & PAGE_PRESENT);
        EXPECT_TRUE(buf->page & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(buf->page));
        EXPECT_EQ(buf->data, 0xb00);
        EXPECT_EQ(*ptr0, 0xbeef);
        buf->cmd = (int) anon_fork_state::PARENT2;
    }
}

int main()
{
    printf("Testing anon... ");
    anon_test();
    printf("success\n");
    wait(NULL);
    printf("Testing file... ");
    file_test();
    printf("success\n");
    wait(NULL);
}
