//
// Created by timo on 08.08.21.
//

#include "PassmanOpensslWrapper.h"
#include <android/log.h>
#include <openssl/evp.h>

#define LOG_TAG "SJCL Wrapper"

PassmanOpensslWrapper::PassmanOpensslWrapper() {
    /* Create and initialise the context */
    if (!(this->ctx = EVP_CIPHER_CTX_new())) {
        throw "error calling EVP_CIPHER_CTX_new";
    }
}

PassmanOpensslWrapper::~PassmanOpensslWrapper() {
    /* Clean up */
    EVP_CIPHER_CTX_free(this->ctx);
}

void PassmanOpensslWrapper::handleErrors(const char *error) {
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, (const char*)"FUCK THIS SHIT GOT AN ERROR: %s", error);
}

int PassmanOpensslWrapper::decryptccm(unsigned char *ciphertext, int ciphertext_len,
                                      unsigned char *aad, int aad_len, unsigned char *tag,
                                      unsigned char *key, unsigned char *iv,
                                      unsigned char *plaintext) {
    int len;
    int ret;

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(this->ctx, EVP_aes_256_ccm(), NULL, NULL, NULL)) {
        handleErrors("Error setting crypto mode");
        return -1;
    }

    int lol = 2;
    if (ciphertext_len >= 1<<16) lol++;
    if (ciphertext_len >= 1<<24) lol++;

    if(1 != EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_CCM_SET_IVLEN, 15-lol, NULL)) {
        handleErrors("Error setting IV Length");
        return -1;
    }

    /* Set expected tag value. */
    if(1 != EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_CCM_SET_TAG, 8, tag)) {
        handleErrors("Error setting TAG value");
        return -1;
    }

    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(this->ctx, NULL, NULL, key, iv)) {
        handleErrors("Error setting KEY and IV");
        return -1;
    }

    /* Provide the total ciphertext length
     */
    if(1 != EVP_DecryptUpdate(this->ctx, NULL, &len, NULL, ciphertext_len)) {
        handleErrors("Error setting cyphertext length");
        return -1;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_DecryptUpdate(this->ctx, NULL, &len, aad, aad_len)) {
        handleErrors("Error setting AAD data");
        return -1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(this->ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (EVP_DecryptUpdate(this->ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) {
        handleErrors("Verify failed");
        return -1;
    }

    /* Success, return plaintext length */
    return len;
}

int PassmanOpensslWrapper::encryptccm(unsigned char *plaintext, int plaintext_len,
                                      unsigned char *aad, int aad_len, unsigned char *key,
                                      unsigned char *iv, int iv_len, unsigned char *ciphertext,
                                      unsigned char *tag, int tag_len) {
    int len;
    int ciphertext_len;

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(this->ctx, EVP_aes_256_ccm(), NULL, NULL, NULL)) {
        handleErrors("Error setting crypto mode");
        return -1;
    }

    /* Set IV length */
    if(1 != EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL)) {
        handleErrors("Error setting IV Length");
        return -1;
    }

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(this->ctx, NULL, NULL, key, iv)) {
        handleErrors("Error setting KEY and IV");
        return -1;
    }

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(this->ctx, NULL, &len, NULL, plaintext_len)) {
        handleErrors("Error setting plaintext length");
        return -1;
    }

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(this->ctx, NULL, &len, aad, aad_len)) {
        handleErrors("Error setting AAD data");
        return -1;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(this->ctx, ciphertext, &len,
                              reinterpret_cast<const unsigned char *>(plaintext), plaintext_len)) {
        handleErrors("Error obtaining the encrypted output");
        return -1;
    }

    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(this->ctx, ciphertext + len, &len)) {
        handleErrors("Error finalizing the encryption");
        return -1;
    }

    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag)) {
        handleErrors("Error getting the encryption tag");
        return -1;
    }

    return ciphertext_len;
}
