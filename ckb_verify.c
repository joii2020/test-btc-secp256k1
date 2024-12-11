#define CKB_C_STDLIB_PRINTF

#include <stdio.h>
#include "ckb_syscalls.h"

#define USE_EXTERNAL_DEFAULT_CALLBACKS
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

#include "secp256k1.c"

#include "modules/recovery/main_impl.h"

#include "precomputed_ecmult.c"

#include "debugger.h"

void secp256k1_default_illegal_callback_fn(const char *str, void *data) {
    (void)str;
    (void)data;
    printf("illegal: %s", str);
    ckb_exit(-102);
}

void secp256k1_default_error_callback_fn(const char *str, void *data) {
    (void)str;
    (void)data;
    printf("error: %s", str);
    ckb_exit(-103);
}

const secp256k1_ge_storage secp256k1_ecmult_gen_prec_table[COMB_BLOCKS]
                                                          [COMB_POINTS];

int secp256k1_verify(uint8_t *sign, uint8_t recid, uint8_t *msg,
                     bool compressed, uint8_t *output_pubkey,
                     size_t *output_pubkey_len) {
    size_t ctx_size =
        secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY);
    uint8_t ctx_buf[ctx_size];
    memset(ctx_buf, 0, ctx_size);

    secp256k1_context *ctx = secp256k1_context_preallocated_create(
        ctx_buf, SECP256K1_CONTEXT_VERIFY);

    if (ctx == NULL) {
        printf("Init secp256k1 failed");
        return 1;
    }

    secp256k1_ecdsa_recoverable_signature signature;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature,
                                                            sign, recid) == 0) {
        return 2;
    }

    secp256k1_pubkey rev_pubkey;
    if (secp256k1_ecdsa_recover(ctx, &rev_pubkey, &signature, msg) != 1) {
        return 3;
    }

    unsigned int flag = SECP256K1_EC_COMPRESSED;
    if (compressed) {
        // output_pubkey_len = SECP256K1_PUBKEY_SIZE;
        *output_pubkey_len = 33;
        flag = SECP256K1_EC_COMPRESSED;
    } else {
        // output_pubkey_len = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
        *output_pubkey_len = 65;
        flag = SECP256K1_EC_UNCOMPRESSED;
    }
    if (secp256k1_ec_pubkey_serialize(ctx, output_pubkey, output_pubkey_len,
                                      &rev_pubkey, flag) != 1) {
        return 4;
    }

    return 0;
}

int main() {
    printf("Begin CKB Verify");

    uint8_t pubkey_hash[] = {0x73, 0x6f, 0xe1, 0xb7, 0x1b, 0xa8, 0x3b,
                             0xed, 0x27, 0xb5, 0x3d, 0xb0, 0x13, 0x9e,
                             0x63, 0x2f, 0x5c, 0x02, 0x64, 0x5f};

    uint8_t sign[] = {
        0x1f, 0xde, 0x58, 0x32, 0x69, 0xa1, 0x67, 0x39, 0x5a, 0xcf, 0x31,
        0x7b, 0xae, 0xcb, 0x4d, 0xbf, 0x89, 0xc5, 0x62, 0xe3, 0xd0, 0x74,
        0x1f, 0xdd, 0x4c, 0xaa, 0x47, 0xd5, 0x31, 0x3f, 0xef, 0x7b, 0x90,
        0x67, 0xa9, 0x93, 0xec, 0xf2, 0xf3, 0x02, 0x2d, 0x09, 0xe3, 0xee,
        0xa3, 0x10, 0x0b, 0x99, 0x67, 0x8a, 0x97, 0xbb, 0x9e, 0x79, 0x46,
        0xfd, 0x0f, 0x9b, 0xa4, 0xdd, 0x78, 0x10, 0x23, 0x60, 0x38};

    // uint8_t msg[] = {0x9a, 0x11, 0x22, 0xa7, 0xc8, 0x65, 0xd6, 0xcd,
    //                  0x7c, 0xc1, 0xa4, 0x48, 0x80, 0x67, 0xe0, 0x21,
    //                  0x5a, 0xa5, 0x89, 0xdd, 0xf7, 0xbe, 0x96, 0xb5,
    //                  0x9b, 0xae, 0x51, 0xfd, 0x59, 0x4f, 0x47, 0x2c};

    uint8_t msg[] = {0xed, 0x79, 0x4a, 0xf3, 0x3d, 0x11, 0xd0, 0x1d,
                     0x63, 0x68, 0x8b, 0xf1, 0x82, 0xcc, 0x24, 0xec,
                     0x16, 0xbf, 0x5f, 0xb0, 0x78, 0xcf, 0x72, 0xcf,
                     0x36, 0xa2, 0xad, 0xe9, 0xad, 0xb7, 0xaf, 0x1e};

    uint8_t recid = sign[0] - 31;
    uint8_t public_key[65] = {0};
    size_t public_key_len = sizeof(public_key);
    secp256k1_verify(sign + 1, recid, msg, true, public_key, &public_key_len);

    print_mem(public_key, public_key_len, "public key");

    return 0;
}