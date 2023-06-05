// This file is dual-licensed.  Choose whichever licence you want from
// the two licences listed below.
//
// The first licence is a regular 2-clause BSD licence.  The second licence
// is the CC-0 from Creative Commons. It is intended to release Monocypher
// to the public domain.  The BSD licence serves as a fallback option.
//
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
//
// ------------------------------------------------------------------------
//
// Copyright (c) 2017-2019, Loup Vaillant
// All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ------------------------------------------------------------------------
//
// Written in 2017-2019 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>
#define TEST_NAME "speed_aead"

#include "speed.h"
#include "sodium.h"

static uint64_t xforro14poly1305(void)
{
    uint8_t out[SIZE];
    uint8_t mac[crypto_aead_xforro14poly1305_ietf_ABYTES];
    RANDOM_INPUT(in, SIZE);
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(nonce, 24);

    TIMING_START
    {
        crypto_aead_xforro14poly1305_ietf_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static uint64_t xchacha20poly1305(void)
{
    uint8_t out[SIZE];
    uint8_t mac[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    RANDOM_INPUT(in, SIZE);
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(nonce, 24);

    TIMING_START
    {
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static uint64_t chacha20poly1305(void)
{
    uint8_t out[SIZE];
    uint8_t mac[crypto_aead_chacha20poly1305_ietf_ABYTES];
    RANDOM_INPUT(in, SIZE);
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(nonce, 24);

    TIMING_START
    {
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static uint64_t aes256gcm(void)
{
    uint8_t out[SIZE];
    uint8_t mac[crypto_aead_aes256gcm_ABYTES];
    RANDOM_INPUT(in, SIZE);
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(nonce, 24);

    TIMING_START
    {
        crypto_aead_aes256gcm_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static uint64_t aegis256(void)
{
    uint8_t out[SIZE];
    uint8_t mac[crypto_aead_aegis256_ABYTES];
    RANDOM_INPUT(in, SIZE);
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(nonce, 24);

    TIMING_START
    {
        crypto_aead_aegis256_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static uint64_t aegis128l(void)
{
    uint8_t out[SIZE];
    uint8_t mac[crypto_aead_aegis128l_ABYTES];
    RANDOM_INPUT(in, SIZE);
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(nonce, 24);

    TIMING_START
    {
        crypto_aead_aegis128l_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

int main()
{
    SODIUM_INIT;
    print("XForro14Poly1305          ", xforro14poly1305() * MUL, "megabytes  per second");
    print("XChacha20Poly1305         ", xchacha20poly1305() * MUL, "megabytes  per second");
    print("Chacha20Poly1305          ", chacha20poly1305() * MUL, "megabytes  per second");
    print("AES256GCM                 ", aes256gcm() * MUL, "megabytes  per second");
    print("Aegis256                  ", aegis256() * MUL, "megabytes  per second");
    print("Aegis128l                 ", aegis128l() * MUL, "megabytes  per second");
    printf("\n");
    return 0;
}
