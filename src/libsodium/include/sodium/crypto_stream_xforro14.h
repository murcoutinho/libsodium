#ifndef crypto_stream_xforro14_H
#define crypto_stream_xforro14_H

/*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 */

#include <stddef.h>
#include <stdint.h>
#include "export.h"

#ifdef __cplusplus
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
extern "C"
{
#endif

#define crypto_stream_xforro14_KEYBYTES 32U
    SODIUM_EXPORT
    size_t crypto_stream_xforro14_keybytes(void);

#define crypto_stream_xforro14_NONCEBYTES 24U
    SODIUM_EXPORT
    size_t crypto_stream_xforro14_noncebytes(void);

#define crypto_stream_xforro14_MESSAGEBYTES_MAX SODIUM_SIZE_MAX
    SODIUM_EXPORT
    size_t crypto_stream_xforro14_messagebytes_max(void);

    SODIUM_EXPORT
    int crypto_stream_xforro14(unsigned char *c, unsigned long long clen,
                               const unsigned char *n, const unsigned char *k)
        __attribute__((nonnull));

    SODIUM_EXPORT
    int crypto_stream_xforro14_xor(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen, const unsigned char *n,
                                   const unsigned char *k)
        __attribute__((nonnull));

    SODIUM_EXPORT
    int crypto_stream_xforro14_xor_ic(unsigned char *c, const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *n, uint64_t ic,
                                      const unsigned char *k)
        __attribute__((nonnull));

    SODIUM_EXPORT
    void crypto_stream_xforro14_keygen(unsigned char k[crypto_stream_xforro14_KEYBYTES])
        __attribute__((nonnull));

#ifdef __cplusplus
}
#endif

#endif
