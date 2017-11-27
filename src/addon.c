#include "common.h"



typedef struct {
  void *_keypair_ptr;
  char _error_msg[256];
  napi_ref _callback;
  napi_async_work _request;
} carrier;

carrier the_carrier;



void Execute(napi_env env, void* data) {

    carrier* c = (carrier*)(data);

    if (c != &the_carrier) {
        napi_throw_type_error(env, NULL, "Wrong data parameter to Execute.");
        return;
    }

    c->_error_msg[0] = '\0';
    c->_keypair_ptr = keypair_ctx_new();
    if(c->_keypair_ptr == NULL) {
        COPY_STRING(c->_error_msg, "Unable to create keypair context");
        return;
    }

    bool created = create_key_pair(c->_keypair_ptr);

    if (!created) {
        keypair_ctx_delete(c->_keypair_ptr);
        COPY_STRING(c->_error_msg, "Failed to create keypair");
    }
    return; 
 
}

void Complete(napi_env env, napi_status status, void* data) {
    
    carrier* c = (carrier*)(data);

    if (c != &the_carrier) {
        napi_throw_type_error(env, NULL, "Wrong data parameter to Complete.");
        return;
    }

    if (status != napi_ok) {
        napi_throw_type_error(env, NULL, "Execute callback failed.");
        return;
    }

    napi_value argv[2];

    struct crypto_keypair_ctx *keypair = (struct crypto_keypair_ctx*)c->_keypair_ptr;

    if (c->_error_msg[0] != '\0') {
        napi_value error;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, c->_error_msg, NAPI_AUTO_LENGTH, &error));
        NAPI_CALL_RETURN_VOID(env, napi_create_error(env, NULL, error, &argv[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &argv[1]));
    } else {

        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &argv[0]));
        // napi_status status;

        napi_value privateKey;
        napi_value private_obj_key;
        napi_value publicKey;
        napi_value public_obj_key;

        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &argv[1]));

        size_t private_key_len = strlen(keypair->private_key);
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, keypair->private_key, private_key_len, &privateKey));

        const char* private_obj_key_name = "privateKey";
        size_t private_obj_key_len = strlen(private_obj_key_name);

        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, private_obj_key_name, private_obj_key_len, &private_obj_key));
        NAPI_CALL_RETURN_VOID(env, napi_set_property(env, argv[1], private_obj_key, privateKey));

        size_t public_key_len = strlen(keypair->public_key);
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, keypair->public_key, public_key_len, &publicKey));

        const char* public_obj_key_name = "publicKey";
        size_t public_obj_key_len = strlen(public_obj_key_name);
        // create public object key name
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, public_obj_key_name, public_obj_key_len, &public_obj_key));
        // set value for publicKey object key
        NAPI_CALL_RETURN_VOID(env, napi_set_property(env, argv[1], public_obj_key, publicKey));
    }

    keypair_ctx_delete(c->_keypair_ptr);

    napi_value callback;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, c->_callback, &callback));
    napi_value global;
    NAPI_CALL_RETURN_VOID(env, napi_get_global(env, &global));

    napi_value result;
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, global, callback, 2, argv, &result));

    NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, c->_callback));
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, c->_request));
}

napi_value CreateKeyPairAsync(napi_env env, napi_callback_info info) {

    size_t argc = 1;
    napi_value argv[1];
    napi_value _this;
    napi_value resource_name;
    void *data;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &_this, &data));
    NAPI_ASSERT(env, argc == 1, "Expected 1 argument.");
    napi_valuetype t;
    NAPI_CALL(env, napi_typeof(env, argv[0], &t));
    NAPI_ASSERT(env, t == napi_function, "First argument must be a function.");
    NAPI_CALL(env, napi_create_reference(env, argv[0], 1, &the_carrier._callback));
    NAPI_CALL(env, napi_create_string_utf8(env, "Crypto::CreateKeyPairAsync", NAPI_AUTO_LENGTH, &resource_name));
    NAPI_CALL(env, napi_create_async_work(env, NULL, resource_name, Execute, Complete, &the_carrier, &the_carrier._request));
    NAPI_CALL(env, napi_queue_async_work(env, the_carrier._request));
    return NULL;
}

napi_value CreateKeyPair(napi_env env, napi_callback_info info) {

    bool created;
    void *keypair_ptr = keypair_ctx_new();
    if (keypair_ptr == NULL) {
        napi_throw_error(env, NULL, "Failed to create ctx for keypair");
        return NULL;    
    }

    if (created = create_key_pair(keypair_ptr) == 0) {
        keypair_ctx_delete(keypair_ptr);
        napi_throw_error(env, NULL, "Failed to create keypair");
        return NULL; 
    };

    struct crypto_keypair_ctx *keypair = (struct crypto_keypair_ctx*)keypair_ptr;

    // napi_status status;
    napi_value keyPair;
    napi_value privateKey;
    napi_value private_obj_key;
    napi_value publicKey;
    napi_value public_obj_key;

    NAPI_CALL(env, napi_create_object(env, &keyPair));

    size_t private_key_len = strlen(keypair->private_key);
    NAPI_CALL(env, napi_create_string_utf8(env, keypair->private_key, private_key_len, &privateKey));

    const char* private_obj_key_name = "privateKey";
    size_t private_obj_key_len = strlen(private_obj_key_name);

    NAPI_CALL(env, napi_create_string_utf8(env, private_obj_key_name, private_obj_key_len, &private_obj_key));
    NAPI_CALL(env, napi_set_property(env, keyPair, private_obj_key, privateKey));

    size_t public_key_len = strlen(keypair->public_key);
    NAPI_CALL(env, napi_create_string_utf8(env, keypair->public_key, public_key_len, &publicKey));

    const char* public_obj_key_name = "publicKey";
    size_t public_obj_key_len = strlen(public_obj_key_name);
    // create public object key name
    NAPI_CALL(env, napi_create_string_utf8(env, public_obj_key_name, public_obj_key_len, &public_obj_key));
    // set value for publicKey object key
    NAPI_CALL(env, napi_set_property(env, keyPair, public_obj_key, publicKey));
    keypair_ctx_delete(keypair_ptr);
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
    char err_buf[256];

    size_t argc = 1;
    napi_value args[1];
    bool isBuffer;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));

    if (argc != 1) {
        napi_throw_error(env, NULL, "Function called with incorrect arguments");
        return NULL;
    }

    napi_valuetype argument_type;
    napi_value params = args[0];
    NAPI_CALL(env, napi_typeof(env, params, &argument_type));
    NAPI_CALL(env, napi_is_buffer(env, params, &isBuffer));

    if (argument_type != napi_object) {
        napi_throw_error(env, NULL, "Expected object as function argument");
        return NULL;
    }

    if (argument_type == napi_object) {
        if (isBuffer) {
            napi_throw_error(env, NULL, "Expected object as function argument but recieved a buffer");
            return NULL;
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
            snprintf(err_buf, 256, "Unable to write cert bio\nReturn value was %d\n", ret);
            goto cleanup;
        }

        if (!(xcert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
            snprintf(err_buf, 256, "Error loading cert into memory\n");
            goto cleanup;
        }

        ret = BIO_write(pkeybio, pk_data, (int)pk_len);
        if (ret < 1 ) {
            snprintf(err_buf, 256, "Unable to write privateKey bio\nReturn value was %d\n", ret);
            goto cleanup;       
        }
        
        if (!(pkey = PEM_read_bio_PrivateKey(pkeybio, NULL, 0, NULL))) {
            snprintf(err_buf, 256, "Error loading private key into memory\n");
            goto cleanup;
        }

        if ((req = X509_to_X509_REQ(xcert, pkey, digest)) == NULL) {
            snprintf(err_buf, 256, "Error converting certificate into request.\n");
            goto cleanup;
        }

        ret = PEM_write_bio_X509_REQ(outbio, req);
        if (ret < 1 ) {
            snprintf(err_buf, 256, "Unable to write CSR bio\nReturn value was %d\n", ret);
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

    cleanup:
    X509_free(xcert);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    BIO_free_all(certbio);
    BIO_free_all(pkeybio);
    napi_throw_error(env, NULL, err_buf);
    return NULL;


};


napi_value GetFingerprint(napi_env env, napi_callback_info info) {

    BIO *certbio = NULL;
    X509 *cert = NULL;
    const EVP_MD *digest;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int i;
    int pos = 0;

    size_t argc = 2;
    napi_value args[2];
    bool isBuffer;
    char *cert_data;
    size_t cert_len;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    NAPI_CALL(env, napi_is_buffer(env, args[0], &isBuffer));

    if (!isBuffer) {
        napi_throw_error(env, NULL, "Certificate is not a buffer");
        return NULL;
    }

    char digest_type[16];
    size_t digestSize = sizeof digest_type;
    size_t digestResult;
    napi_value digest_arg = args[1];

    if(argc == 1) {
        NAPI_CALL(env, napi_create_string_utf8(env, (char *)"sha1", -1, &digest_arg));
    } 

    NAPI_CALL(env, napi_get_value_string_utf8(env, digest_arg, (char *)digest_type, digestSize, &digestResult));

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

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("createKeyPair", CreateKeyPair),
        DECLARE_NAPI_PROPERTY("createKeyPairAsync", CreateKeyPairAsync),
        DECLARE_NAPI_PROPERTY("createCSR", CreateCSR),
        DECLARE_NAPI_PROPERTY("getFingerprint", GetFingerprint),

    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
};

NAPI_MODULE(addon, Init)
