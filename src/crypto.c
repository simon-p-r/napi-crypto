#include "crypto.h"



napi_value CreateKeyPair(napi_env env, napi_callback_info info) {

    RSA *rsa = NULL;
    BIO *bio;
    BIGNUM *bn = NULL;
    char *raw;
    long rawLength;
    int bits = 4096;
    unsigned long exponent = RSA_F4;

    // napi_status status;
    napi_value keyPair;
    napi_value privateKey;
    napi_value private_obj_key;
    napi_value publicKey;
    napi_value public_obj_key;

    NAPI_CALL(env, napi_create_object(env, &keyPair));

    /* Generate key */
    int ret = 0;
    bn = BN_new();
    ret = BN_set_word(bn, exponent);
    if (ret != 1) {
        BN_free(bn);
        napi_throw_error(env, NULL, "Failed to generate big num");
        return NULL;
    }
    
    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bn, NULL);
    if (ret != 1) {
        BN_free(bn);
        RSA_free(rsa);
        napi_throw_error(env, NULL, "Failed to generate key");
        return NULL;
    }

    BN_free(bn);

    /* Allocate BIO */
    bio = BIO_new(BIO_s_mem());

    /* Dump private key */
    if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL)) {
        RSA_free(rsa);
        BIO_vfree(bio);
        napi_throw_error(env, NULL, "Failed to write private key");
        return NULL;
    }

    rawLength = BIO_get_mem_data(bio, &raw);
    NAPI_CALL(env, napi_create_string_utf8(env, raw, rawLength, &privateKey));

    const char* private_obj_key_name = "privateKey";
    size_t private_obj_key_len = strlen(private_obj_key_name);

    NAPI_CALL(env, napi_create_string_utf8(env, private_obj_key_name, private_obj_key_len, &private_obj_key));

    NAPI_CALL(env, napi_set_property(env, keyPair, private_obj_key, privateKey));

    /* Reallocate BIO */
    BIO_vfree(bio);
    bio = BIO_new(BIO_s_mem());

    if (bio == NULL) {
        napi_throw_error(env, NULL, "Failed to create bio");
        return NULL;
    }

    /* Dump public key */
    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa)) {
        BIO_vfree(bio);
        RSA_free(rsa);
        napi_throw_error(env, NULL, "Failed to write public key");
        return NULL;
    }

    rawLength = BIO_get_mem_data(bio, &raw);
    NAPI_CALL(env, napi_create_string_utf8(env, raw, rawLength, &publicKey));

    const char* public_obj_key_name = "publicKey";
    size_t public_obj_key_len = strlen(public_obj_key_name);
    // create public object key name
    NAPI_CALL(env, napi_create_string_utf8(env, public_obj_key_name, public_obj_key_len, &public_obj_key));
    // set value for publicKey object key
    NAPI_CALL(env, napi_set_property(env, keyPair, public_obj_key, publicKey));

    BIO_vfree(bio);
    return keyPair;
};



napi_value CreateCSR(napi_env env, napi_callback_info info) {

    BIO *certbio = NULL;
    BIO *pkeybio = NULL;
    BIO *outbio = NULL;
    X509 *xcert = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *digest = EVP_sha256();

    size_t argc = 1;
    napi_value args[1];
    bool isBuffer;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc == 1) {

        napi_valuetype argument_type;
        napi_value params = args[0];
        NAPI_CALL(env, napi_typeof(env, params, &argument_type));
        NAPI_CALL(env, napi_is_buffer(env, params, &isBuffer));

        if (argument_type == napi_object) {
            if (isBuffer) {
                goto exit;
            }

            char *pk_data;
            size_t pk_len;
            napi_value privateKey;
            napi_value private_obj_key;
            const char* private_key_name = "privateKey";
            size_t private_obj_key_len = strlen(private_key_name);
            // create public object key name
            NAPI_CALL(env, napi_create_string_utf8(env, private_key_name, private_obj_key_len, &private_obj_key));
            NAPI_CALL(env, napi_get_property(env, params, private_obj_key, &privateKey));
            NAPI_CALL(env, napi_is_buffer(env, privateKey, &isBuffer));

            if (isBuffer) {
                NAPI_CALL(env, napi_get_buffer_info(env, privateKey, (void**)(&pk_data), &pk_len));
            }
        
            char *cert_data;
            size_t cert_len;
            napi_value cert;
            napi_value cert_obj_key;
            const char* cert_key_name = "certificate";
            size_t cert_obj_key_len = strlen(cert_key_name);
            // create public object key name
            NAPI_CALL(env, napi_create_string_utf8(env, cert_key_name, cert_obj_key_len, &cert_obj_key));
            NAPI_CALL(env, napi_get_property(env, params, cert_obj_key, &cert));
            NAPI_CALL(env, napi_is_buffer(env, cert, &isBuffer));

            if (isBuffer) {
                NAPI_CALL(env, napi_get_buffer_info(env, cert, (void**)(&cert_data), &cert_len));
            }
        
            // read existing 
            pkeybio = BIO_new(BIO_s_mem());
            certbio = BIO_new(BIO_s_mem());
            outbio = BIO_new(BIO_s_mem());
            
            int ret = 0;
            ret = BIO_write(certbio, cert_data, (int)cert_len);
            if (ret < 1 ) {
                printf("Unable to write cert bio\nReturn value was %d\n", ret);
                goto cleanup;       
            }

            if (!(xcert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
                printf("Error loading cert into memory\n");
                goto cleanup;
            }

            ret = BIO_write(pkeybio, pk_data, (int)pk_len);
            if (ret < 1 ) {
                printf("Unable to write privateKey bio\nReturn value was %d\n", ret);
                goto cleanup;       
            }
          
            if (!(pkey = PEM_read_bio_PrivateKey(pkeybio, NULL, 0, NULL))) {
                printf("Error loading private key into memory\n");
                goto cleanup;
            }

            if ((req = X509_to_X509_REQ(xcert, pkey, digest)) == NULL) {
                printf("Error converting certificate into request.\n");
                goto cleanup;
            }

            ret = PEM_write_bio_X509_REQ(outbio, req);
            if (ret < 1 ) {
                printf("Unable to write CSR bio\nReturn value was %d\n", ret);
                goto cleanup;       
            }

            char *csr;
            napi_value csrBuffer;
            NAPI_CALL(env, napi_create_buffer(env, outbio->num_write, (void**)(&csr), &csrBuffer));
            BIO_read(outbio, csr, outbio->num_write);

            X509_free(xcert);
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            BIO_free_all(certbio);
            BIO_free_all(pkeybio);         
            return csrBuffer;
        }

    } 

    goto exit;

    cleanup:
    X509_free(xcert);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    BIO_free_all(certbio);
    BIO_free_all(pkeybio);
    return NULL;

    exit:
    napi_throw_error(env, NULL, "Function called with no arguments");
    return NULL;
};


napi_value GetFingerprint(napi_env env, napi_callback_info info) {

    BIO *certbio = NULL;
    X509 *cert = NULL;
    const EVP_MD *digest;
    unsigned char md[EVP_MAX_MD_SIZE];
    int i;
    int pos = 0;

    size_t argc = 2;
    napi_value args[2];
    bool isBuffer;
    char *cert_data;
    size_t cert_len;


    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    char digest_type[16];
    size_t digestSize = sizeof digest_type;
    size_t digestResult;
    napi_value digest_arg = args[1];

    if(argc != 2) {
        NAPI_CALL(env, napi_create_string_utf8(env, (char *)"sha1", -1, &digest_arg));
    } 

    NAPI_CALL(env, napi_get_value_uint32(env, digest_arg, (char *)digest_type, digestSize, &digestResult));

    if (strcmp("md5", digest_type) == 0) {
        digest = EVP_md5();
    } else if(strcmp("sha1", digest_type) == 0) {
        digest = EVP_sha1();
    } else if(strcmp("sha256", digest_type) == 0) {
        digest = EVP_sha256();
    } else if(strcmp("sha512", digest_type) == 0) {
        digest = EVP_sha512();
    } else {
        napi_throw_error(env, NULL, "Digest type is invalid");
        return NULL;
    }

    NAPI_CALL(env, napi_is_buffer(env, args[0], &isBuffer));

    if (!isBuffer) {
        napi_throw_error(env, NULL, "Certificate is not a buffer");
        return NULL;
    }

    NAPI_CALL(env, napi_get_buffer_info(env, args[0], (void**)(&cert_data), &cert_len));
    certbio = BIO_new_mem_buf(cert_data, (int)cert_len);

    if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_free(certbio);
        napi_throw_error(env, NULL, "Error loading cert into memory");
        return NULL;
    }

    uint8_t size[EVP_MAX_MD_SIZE * 4];
    memset(size, 0x00, sizeof(size));
    uint32_t len = sizeof(size);
    char fingerprint_string[EVP_MAX_MD_SIZE * 4];
    uint32_t buflen = sizeof(fingerprint_string);


    if (!X509_digest(cert, digest, md, &len)) {
        BIO_free(certbio);
        napi_throw_error(env, NULL, "Error getting cert digest");
        return NULL;
    }

      for(i = 0; i < len; ++i) {
        if (i > 0) {
          pos += snprintf(fingerprint_string + pos, buflen - pos, ":");
        }
        pos += snprintf(fingerprint_string + pos, buflen - pos, "%02X", md[i]);
      }


    napi_value fingerprint;
    NAPI_CALL(env, napi_create_string_utf8(env, fingerprint_string, strlen(fingerprint_string), &fingerprint));
    return fingerprint;

};


napi_value CreateSelfSignedCert(napi_env env, napi_callback_info info) {

    return NULL;
};




napi_value Init(napi_env env, napi_value exports) {

    napi_value createKeyPair;
    // set CreateKeyPair func to exports
    NAPI_CALL(env, napi_create_function(env, "createKeyPair", -1, CreateKeyPair, NULL, &createKeyPair));
    // set CreateKeyPair func to property name on exports object, if not used func would be the native object itself and not child node
    NAPI_CALL(env, napi_set_named_property(env, exports, "createKeyPair", createKeyPair));

    napi_value createCSR;
    // set CreateCSR func to exports
    NAPI_CALL(env, napi_create_function(env, "createCSR", -1, CreateCSR, NULL, &createCSR));
    // set CreateCSR func to property name on exports object, if not used func would be the native object itself and not child node
    NAPI_CALL(env, napi_set_named_property(env, exports, "createCSR", createCSR));


    napi_value getFingerprint;
    // set CreateCSR func to exports
    NAPI_CALL(env, napi_create_function(env, "getFingerprint", -1, GetFingerprint, NULL, &getFingerprint));
    // set CreateCSR func to property name on exports object, if not used func would be the native object itself and not child node
    NAPI_CALL(env, napi_set_named_property(env, exports, "getFingerprint", getFingerprint));

    return exports;
  
  };




  
  NAPI_MODULE(addon, Init)
