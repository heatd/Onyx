/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// clang-format off
#include <stdlib.h>
#include <cstddef>

#include <gtest/gtest.h>

// Compile using:
// g++ -O2 kernel/lib/libk/tests/host_folly_memset.cpp kernel/lib/libk/arch/x86_64/memset.S
// -lgtest -lgtest_main -I kernel/include/

constexpr size_t kPageSize = 4096;
constexpr size_t kMaxSize = 2 * kPageSize;
constexpr uint8_t kBufEnd = 0xDB;

extern "C" void *__memset(void*, int, size_t);
// memset implementation test with 0xFF pattern
// buf must have an extra byte to be filled with magic constant
void testMemsetImpl(uint8_t* buf, size_t maxLen) {
  for (size_t len = 0; len < maxLen; len++) {
    for (size_t i = 0; i < maxLen; i++) {
      buf[i] = 0x0;
    }
    buf[len] = kBufEnd;
    auto* p = __memset(buf, 0xFF, len);
    EXPECT_EQ(buf, reinterpret_cast<uint8_t*>(p));
    bool isEq = true;
    for (size_t i = 0; i < len; i++) {
      EXPECT_EQ(buf[i], 0xFF) << "buf[" << i << "]\n";
    }

    EXPECT_EQ(buf[len], kBufEnd);
  }
}

TEST(MemsetAsmTest, alignedBuffer) {
  uint8_t* buf = reinterpret_cast<uint8_t*>(
      aligned_alloc(kPageSize, kMaxSize + 2 * kPageSize));
  // Get buffer aligned power of 2 from 16 all the way up to a page size
  for (size_t alignment = 16; alignment <= kPageSize; alignment <<= 1) {
    testMemsetImpl(buf + (alignment % kPageSize), kMaxSize);
  }
  free(buf);
}

TEST(MemsetAsmTest, unalignedBuffer) {
  uint8_t* buf = reinterpret_cast<uint8_t*>(
      aligned_alloc(kPageSize, kMaxSize + 2 * kPageSize));
  for (size_t alignment = 1; alignment <= 192; alignment++) {
    testMemsetImpl(buf + alignment, kMaxSize);
  }
  free(buf);
}
