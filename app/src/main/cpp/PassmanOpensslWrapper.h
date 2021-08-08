//
// Created by timo on 08.08.21.
//

#ifndef PASSMAN_ANDROID_PASSMANOPENSSLWRAPPER_H
#define PASSMAN_ANDROID_PASSMANOPENSSLWRAPPER_H


#include <openssl/evp.h>

class PassmanOpensslWrapper {
public:
        PassmanOpensslWrapper();
        ~PassmanOpensslWrapper();
        int decryptccm(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
                   int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
                   unsigned char *plaintext
        );
        int encryptccm(unsigned char *plaintext, int plaintext_len,
                       unsigned char *aad, int aad_len, unsigned char *key,
                       unsigned char *iv, int iv_len, unsigned char *ciphertext,
                       unsigned char *tag, int tag_len);
    private:
        EVP_CIPHER_CTX *ctx;
        static void handleErrors(const char* error);
};


#endif //PASSMAN_ANDROID_PASSMANOPENSSLWRAPPER_H
