/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <signal.h>

#include <gtest/gtest.h>

static bool valid_arm64_ctx(_aarch64_ctx *ctx)
{
    switch (ctx->magic)
    {
        case FPSIMD_MAGIC:
            return ctx->size == sizeof(fpsimd_context);
        case ESR_MAGIC:
            return ctx->size == sizeof(esr_context);
        default:
#ifdef __onyx__
            // Onyx does not have anything else implemented
            return false;
#else
            return true;
#endif
    }
}

static sig_atomic_t got_sig = 0;

TEST(signal, gpr_context_saving)
{
    // Register ourselves for a SIGILL, change the context deliberately, and then udf. In the signal
    // handler, check the context for consistency.

    got_sig = 0;
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = [](int signo, siginfo_t *siginfo, void *uctx) {
        mcontext_t *mctx = &((ucontext_t *) uctx)->uc_mcontext;

        got_sig = 1;

        for (unsigned long i = 0; i < 31; i++)
        {
            EXPECT_EQ(mctx->regs[i], i);
        }

        uint8_t *ptr = (uint8_t *) mctx->__reserved;

        for (;;)
        {
            _aarch64_ctx *ctx = (_aarch64_ctx *) ptr;
            if (ctx->magic == 0)
            {
                EXPECT_EQ(ctx->size, 0);
                break;
            }

            EXPECT_GT(ctx->size, 0);
            EXPECT_LT(ctx->size, sizeof(mctx->__reserved));
            EXPECT_FALSE(ptr + ctx->size >=
                         (uint8_t *) mctx->__reserved + sizeof(mctx->__reserved));
            EXPECT_TRUE(valid_arm64_ctx(ctx));

            ptr += ctx->size;
        }

        mctx->pc += 4;
    };

    sigemptyset(&sa.sa_mask);

    ASSERT_EQ(sigaction(SIGILL, &sa, nullptr), 0);

    __asm__ __volatile__("mov x0, #0\n\t"
                         "mov x1, #1\n\t"
                         "mov x2, #2\n\t"
                         "mov x3, #3\n\t"
                         "mov x4, #4\n\t"
                         "mov x5, #5\n\t"
                         "mov x6, #6\n\t"
                         "mov x7, #7\n\t"
                         "mov x8, #8\n\t"
                         "mov x9, #9\n\t"
                         "mov x10, #10\n\t"
                         "mov x11, #11\n\t"
                         "mov x12, #12\n\t"
                         "mov x13, #13\n\t"
                         "mov x14, #14\n\t"
                         "mov x15, #15\n\t"
                         "mov x16, #16\n\t"
                         "mov x17, #17\n\t"
                         "mov x18, #18\n\t"
                         "mov x19, #19\n\t"
                         "mov x20, #20\n\t"
                         "mov x21, #21\n\t"
                         "mov x22, #22\n\t"
                         "mov x23, #23\n\t"
                         "mov x24, #24\n\t"
                         "mov x25, #25\n\t"
                         "mov x26, #26\n\t"
                         "mov x27, #27\n\t"
                         "mov x28, #28\n\t"
                         "mov x29, #29\n\t"
                         "mov x30, #30\n\t"
                         "udf #1\n\t" ::
                             : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
                               "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
                               "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
                               "x30");
    EXPECT_EQ(got_sig, 1);
    got_sig = 0;
    ASSERT_NE(signal(SIGILL, SIG_DFL), SIG_ERR);
}

TEST(signal, brk_signal)
{
    got_sig = 0;
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = [](int signo, siginfo_t *siginfo, void *uctx) {
        mcontext_t *mctx = &((ucontext_t *) uctx)->uc_mcontext;

        got_sig = 1;
        EXPECT_EQ(siginfo->si_code, TRAP_BRKPT);
        mctx->pc += 4;
    };

    sigemptyset(&sa.sa_mask);

    ASSERT_EQ(sigaction(SIGTRAP, &sa, nullptr), 0);

    __asm__ __volatile__("brk #0");

    EXPECT_EQ(got_sig, 1);
    got_sig = 0;
    ASSERT_NE(signal(SIGTRAP, SIG_DFL), SIG_ERR);
}

// TODO(pedro): Test for bad sigreturns
