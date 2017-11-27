

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "common.h"

#ifdef _WIN32
#ifndef CRYPTO_STRDUP
#define CRYPTO_STRDUP(source) _strdup(source) 
#endif
#else
#ifndef CRYPTO_STRDUP
#define CRYPTO_STRDUP(source) strdup(source) 
#endif
#endif


void *keypair_ctx_new() {
    
    struct crypto_keypair_ctx *keypair = calloc(1, sizeof(struct crypto_keypair_ctx));
    if (keypair == NULL) {
        return NULL;
    }

    keypair->error_msg[0] = '\0';
    return (void*)keypair;

};


void keypair_ctx_delete(void *ctx) {
    
    struct crypto_keypair_ctx *keypair = (struct crypto_keypair_ctx*)ctx;

    if(keypair != NULL) {
        if(keypair->private_key != NULL) {
            free(keypair->private_key);
        }
        if(keypair->public_key != NULL) {
            free(keypair->public_key);
        }
        free(keypair);
    }

}



bool create_key_pair(void *ctx) {

    struct crypto_keypair_ctx *keypair = (struct crypto_keypair_ctx*)ctx;

    RSA *rsa = NULL;
    BIO *bio;
    BIGNUM *bn = NULL;
    char *private_key;
    char *public_key;
    long rawLength;
    int bits = 4096;
    unsigned long exponent = RSA_F4;

    /* Generate key */
    int ret = 0;
    bn = BN_new();
    ret = BN_set_word(bn, exponent);

    if (ret != 1) {
        BN_free(bn);
        COPY_STRING(keypair->error_msg, "Failed to generate big num");
        return false;
    }
    
    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bn, NULL);

    if (ret != 1) {
        BN_free(bn);
        RSA_free(rsa);
        COPY_STRING(keypair->error_msg, "Failed to generate key");
        return false;
    }

    BN_free(bn);

    /* Allocate BIO */
    bio = BIO_new(BIO_s_mem());

    /* Dump private key */

    if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL)) {
        RSA_free(rsa);
        BIO_vfree(bio);
        COPY_STRING(keypair->error_msg, "Failed to write private key");
        return false;
    }

    rawLength = BIO_get_mem_data(bio, &private_key);
    keypair->private_key = CRYPTO_STRDUP(private_key);

    /* Reallocate BIO */
    BIO_vfree(bio);
    bio = BIO_new(BIO_s_mem());

    if (bio == NULL) {
        COPY_STRING(keypair->error_msg, "Failed to create bio");
        return false;
    }

    /* Dump public key */

    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa)) {
        BIO_vfree(bio);
        RSA_free(rsa);
        COPY_STRING(keypair->error_msg, "Failed to write public key");
        return false;
    }

    rawLength = BIO_get_mem_data(bio, &public_key);
    keypair->public_key = CRYPTO_STRDUP(public_key);
    BIO_vfree(bio);
    return true;

}


