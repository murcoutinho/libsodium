
#define TEST_NAME "xforro14"
#include "cmptest.h"
typedef struct Hforro14TV_
{
    const char key[crypto_core_hforro14_KEYBYTES * 2 + 1];
    const char in[crypto_core_hforro14_INPUTBYTES * 2 + 1];
    const char out[crypto_core_hforro14_OUTPUTBYTES * 2 + 1];
} Hforro14TV;

static void
tv_hforro14(void)
{
    static const Hforro14TV tvs[] = {
        {"fb5c38aeebfbf405f0a60b2296bfdf1a07b556fbc32ccb65b7a21de1b0fb007b", "6863370d90ce0bde35aec0088feace1a", "d5dec1229b1cea3efdd0382cf39e2cf79ccfdfdf400d0de0b6392c0d89d345bf"},
        {"18c34ee0ed3cf9bd9de5793b322a49427f57a86ac336b4ec1a1795aaeb20a252", "e362bcad548ac003aad3ba46ef1607e1", "471b776295f81f482293fbf893fca4555317d3b641940c2a668a5181b96e034e"},
        {"b37953420d6b02c5040ea748e132df76f7d155823f5d97763461b424034e1478", "5bd935c83d133210d9de9aae9d651441", "47b9340edc1ac8ecc7b51dc59040685c3d198914d01242f1b176696b3a69bc5a"},
        {"9bff51f895dd2da93864f43525eec5d62e8e83f5f5b5c682e520f6f2d7498937", "65530a0cbde7e040c891db5ff6008d2d", "a97b9facbbf4ac991d69775be2b0ba091333aadaf4c90710ee30043682ffdedc"},
        {"0809d203ed3571ff3aa4ec4f6fc1de10b92e87c76f4b4ffdfad8fe37381d9d67", "8aa6100dda567d04614db23e38e548db", "86adf65f128dec98187848336a79e7fa64230964ce353b780df7a5ff626c284e"},
        {"1eb598146ce623ad2f9862d71f7ac79ea7e4731b794ed28e32a8327831364309", "3ad23370a9be92f5c0e316f041becef6", "846c8a63d4c476ec3948ca90cad543f93ff7dde95bc81a0182ac2b2006ef72a7"},
        {"6b0ab6913ac0be730e2a55df94a25de7ee45df5bb12e39e82d5ecc89e06835a5", "30c3e2daf14197054dc24097747cdecc", "ad2231711156eb532118f0c000b0573515951461ee9144e67a7e29c475e7fcbe"},
        {"342b874ca9a4103c1b4d7c1435a602fd7e6e31f3352468fb4d6d3635cf887f66", "41fa687d949788ca4305f4118d068150", "9a4fe98c098a5ccfcc9c59ae6c03e1fbf101b37cf0b2e2af6c8a4565647c0f30"},
        {"2b90f875fc53683fa2bb3c0f592f2040ed0bb3db5e63817e15312518d7d0c458", "a255722a92b7c63f1292f4fef8cb0146", "59c28cec1721424ad91699999c424bf20ec210f216439558b1bd987b1a383401"},
        {"be875e8fd7ac02a9dd861b0f0c9be1b9c2df0dcbe131536ad0d08cde49de6e77", "7b155d82389c755f53ee85194da1c08f", "622bbddbc2490a14c168f2a086cd41345759804ebdb0fa3ed6bf25211910636e"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000090000004a0000000031415927", "9754128339bd105377908eb53d7f238e7b3732cc48383052d35fd94c943db866"}};
    const Hforro14TV *tv;
    unsigned char *constant;
    unsigned char *key;
    unsigned char *in;
    unsigned char *out;
    unsigned char *out2;
    size_t i;

    key = (unsigned char *)sodium_malloc(crypto_core_hforro14_KEYBYTES);
    in = (unsigned char *)sodium_malloc(crypto_core_hforro14_INPUTBYTES);
    out = (unsigned char *)sodium_malloc(crypto_core_hforro14_OUTPUTBYTES);
    out2 = (unsigned char *)sodium_malloc(crypto_core_hforro14_OUTPUTBYTES);

    for (i = 0; i < (sizeof tvs) / (sizeof tvs[0]); i++)
    {
        tv = &tvs[i];
        sodium_hex2bin(key, crypto_core_hforro14_KEYBYTES,
                       tv->key, strlen(tv->key), NULL, NULL, NULL);
        sodium_hex2bin(in, crypto_core_hforro14_INPUTBYTES,
                       tv->in, strlen(tv->in), NULL, NULL, NULL);
        sodium_hex2bin(out, crypto_core_hforro14_OUTPUTBYTES,
                       tv->out, strlen(tv->out), NULL, NULL, NULL);
        crypto_core_hforro14(out2, in, key);
        assert(memcmp(out, out2, crypto_core_hforro14_OUTPUTBYTES) == 0);
    }

    sodium_free(out2);
    sodium_free(out);
    sodium_free(in);
    sodium_free(key);

    assert(crypto_core_hforro14_outputbytes() == crypto_core_hforro14_OUTPUTBYTES);
    assert(crypto_core_hforro14_inputbytes() == crypto_core_hforro14_INPUTBYTES);
    assert(crypto_core_hforro14_keybytes() == crypto_core_hforro14_KEYBYTES);
    assert(crypto_core_hforro14_constbytes() == crypto_core_hforro14_CONSTBYTES);

    printf("tv_hforro14: ok\n");
}

#define Xforro14_OUT_MAX 100

typedef struct Xforro14TV_
{
    const char key[crypto_stream_xforro14_KEYBYTES * 2 + 1];
    const char nonce[crypto_stream_xforro14_NONCEBYTES * 2 + 1];
    const char out[Xforro14_OUT_MAX * 2 + 1];
} Xforro14TV;

static void
tv_stream_xforro14(void)
{
    static const Xforro14TV tvs[] = {
        {"446a5599971cbbc8c4c5379f012be204d73d977af5cfdf18e1c4f6e52bb2f948", "b90ae2af0d3158b0a5625a7330e8d8837a6e3edc294986af", "99e194672b129f5b9de57406c3e91d65be0c81a1e5b43882a26b128523"},
        {"5400df2a2368cd0208707b0d98be2ae1e2f86059262a633bf16385aafbb7355b", "1b04612a71d647e9afbdefa2e8b4246a9f3873a90b7a262f", "49eae0227d88af889d004aca095ec2fea32725a2c45b4d01e427baeb"},
        {"99f2e5cd47bef485725b6e79fa942d11bfd74c064829265cd2518d12e6cce1c3", "02c8f41fa64a64b158b7e8df76ac719ffdb399adc9e47bf4", "95fe548b5c0f4199ef3552c2e9dead337a48fd978ed4"},
        {"102326ecaef535a79df587c1d42754b9331fc385958f69a5ddf16fe13a3ab47b", "2bbf7a342c717330d79e6c8f729d88169d109972f27c7d92", "2d74b8e05dfc7eb1a644a980acd60833d13345c90e26111e4b2cf25e0dc0eb683f3243e7a1750f8287d0374a5272fe0c38592e3f1dd82d104d"},
        {"2002c6fd52320bcc96bb60fb947556448033c377ca6319e200e5bcd90952f418", "eeacd80edb362c44c12d4c91e9043e28f4da21b590f99ebc", "f87b51ea783083b3bac7b29f51054a5ee9cfffba6f1039229a85971da26cf3996336fb88d60b51bb43e1d2b93008bc12"},
        {"39df4665ba6c0c5bf34f0480640ea6490ffbebef6e7cbc8940e8c6108584351d", "5dfe6d3747bf965b8691a206100c5f5404177f2879eeeb02", "5e6e1b9d8e26c45e08df7aa2b3e98f027600e69266ee92d96e6526532ff255"},
        {"d130c9253c4900d662278106d726b6d2ed849767ca51765e222f1ce5f2085a84", "9b60136a07315bf14eb36748a871cb2ecaac68102a17c388", "39cd2e7d418cc7aa91140486a5c893363361b750c6f5b5c00134754cb9fe2619de5a6e832248"},
        {"179042a891328da594339db39828b5d3699a838a96b012d7b68976bc8d916fc3", "b6c1d879c52fd5b5ec25b87acd97e94f2ab544e5be5bf98e", "fee72ec18e2a4aceaeab6a7974b7e1e3295f7d603a7f59a965474f5b06b1d7004ce43b0bdfc1de9b076d1392b229a5873c5bbd6ab23c19bb8d8351abf7ea304afde77bcec161ae0c8f6e92a8"},
        {"a759f38844b8ee3398360cf1d775b7ed6ab4a98ed49548681286146aad69c67c", "6bbcbd49d217cb91d0571a9230a14d3566929f03ba10f643", "d07997243a63b110379e0cdc29a7c0fc8d7526ffaf076bf3836c746ccc102b1b3df52eeab8daa83df06eb4d5217ce3d8c43da209"},
        {"3259b24feaa3a0c0079bef16e5df335e9a6aac9f61602d2bd736ae25f662fe31", "fda7570713c45f69559c1ca725d2bc10723ea972b1e5c77c", "f4fc5bc1b2fda1b58eb5e521c84c0efc5357c4adfeb7542237bac0b3a69e4d6dfc7b08da3dee6d73e810a4d4c25be591ee6ba1087e0970eb6899da9ff5b29cca3fb32d2ac32566f2be9919b089cdc41e586072305cc09e3a06510c"}
    };
    const Xforro14TV *tv;
    char *hex;
    unsigned char *key;
    unsigned char *nonce;
    unsigned char *out;
    unsigned char *out2;
    size_t out_len;
    size_t i;

    key = (unsigned char *)sodium_malloc(crypto_stream_xforro14_KEYBYTES);
    nonce = (unsigned char *)sodium_malloc(crypto_stream_xforro14_NONCEBYTES);
    out = (unsigned char *)sodium_malloc(Xforro14_OUT_MAX);
    for (i = 0; i < (sizeof tvs) / (sizeof tvs[0]); i++)
    {
        tv = &tvs[i];

        sodium_hex2bin(key, crypto_stream_xforro14_KEYBYTES,
                       tv->key, strlen(tv->key), NULL, NULL, NULL);
        sodium_hex2bin(nonce, crypto_stream_xforro14_NONCEBYTES,
                       tv->nonce, strlen(tv->nonce), NULL, NULL, NULL);
        sodium_hex2bin(out, Xforro14_OUT_MAX,
                       tv->out, strlen(tv->out), NULL, &out_len, NULL);
        out2 = (unsigned char *)sodium_malloc(out_len);
        crypto_stream_xforro14(out2, out_len, nonce, key);
        assert(memcmp(out, out2, out_len) == 0);
        crypto_stream_xforro14_xor(out2, out, out_len, nonce, key);
        assert(sodium_is_zero(out2, out_len));
        crypto_stream_xforro14_xor_ic(out2, out, out_len, nonce, 0, key);
        assert(sodium_is_zero(out2, out_len));
        crypto_stream_xforro14_xor_ic(out2, out, out_len, nonce, 1, key);
        assert(!sodium_is_zero(out2, out_len));
        crypto_stream_xforro14_xor(out, out, out_len, nonce, key);
        assert(sodium_is_zero(out, out_len));
        sodium_free(out2);
    }

    out2 = (unsigned char *)sodium_malloc(0);
    crypto_stream_xforro14(out2, 0, nonce, key);
    crypto_stream_xforro14_xor(out2, out2, 0, nonce, key);
    crypto_stream_xforro14_xor_ic(out2, out2, 0, nonce, 1, key);
    sodium_free(out2);
    sodium_free(out);

    out = (unsigned char *)sodium_malloc(64);
    out2 = (unsigned char *)sodium_malloc(128);
    randombytes_buf(out, 64);
    randombytes_buf(out2, 64);
    memcpy(out2 + 64, out, 64);
    crypto_stream_xforro14_xor_ic(out, out, 64, nonce, 1, key);
    crypto_stream_xforro14_xor(out2, out2, 128, nonce, key);
    assert(memcmp(out, out2 + 64, 64) == 0);
    sodium_free(out);
    sodium_free(out2);

    out = (unsigned char *)sodium_malloc(192);
    out2 = (unsigned char *)sodium_malloc(192);
    memset(out, 0, 192);
    memset(out2, 0, 192);
    crypto_stream_xforro14_xor_ic(out2, out2, 192, nonce,
                                  (1ULL << 32) - 1ULL, key);
    crypto_stream_xforro14_xor_ic(out, out, 64, nonce,
                                  (1ULL << 32) - 1ULL, key);
    crypto_stream_xforro14_xor_ic(out + 64, out + 64, 64, nonce,
                                  (1ULL << 32), key);
    crypto_stream_xforro14_xor_ic(out + 128, out + 128, 64, nonce,
                                  (1ULL << 32) + 1, key);
    assert(memcmp(out, out2, 192) == 0);
    hex = (char *)sodium_malloc(192 * 2 + 1);
    sodium_bin2hex(hex, 192 * 2 + 1, out, 192);
    printf("%s\n", hex);

    memset(key, 0, crypto_stream_xforro14_KEYBYTES);
    crypto_stream_xforro14_keygen(key);
    assert(sodium_is_zero(key, crypto_stream_xforro14_KEYBYTES) == 0);

    sodium_free(hex);
    sodium_free(out);
    sodium_free(out2);

    sodium_free(nonce);
    sodium_free(key);

    assert(crypto_stream_xforro14_keybytes() == crypto_stream_xforro14_KEYBYTES);
    assert(crypto_stream_xforro14_noncebytes() == crypto_stream_xforro14_NONCEBYTES);
    assert(crypto_stream_xforro14_messagebytes_max() == crypto_stream_xforro14_MESSAGEBYTES_MAX);

    printf("tv_stream_xforro14: ok\n");
}

int
main(void)
{
    tv_hforro14();
    tv_stream_xforro14();

    return 0;
}
