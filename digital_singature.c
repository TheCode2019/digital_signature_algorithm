#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define SIGN_SIZE 256

// generate RSA key pair
RSA *generate_key_pair(int key_length) {
    RSA *key_pair = RSA_new();
    BIGNUM *bn = BN_new();
    if (RSA_generate_key_ex(key_pair, key_length, bn, NULL) != 1) {
        printf("Error generating RSA key pair\n");
        return NULL;
    }
    return key_pair;
}

// sign message using private key
unsigned char *sign_message(RSA *private_key, unsigned char *message, int message_length) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit(md_ctx, EVP_sha256()) != 1) {
        printf("Error initializing message digest context\n");
        return NULL;
    }
    if (EVP_DigestUpdate(md_ctx, message, message_length) != 1) {
        printf("Error updating message digest\n");
        return NULL;
    }
    unsigned int sign_length;
    unsigned char *sign = malloc(SIGN_SIZE);
    if (RSA_sign(NID_sha256, md_ctx->md_data, EVP_MD_size(EVP_sha256()), sign, &sign_length, private_key) != 1) {
        printf("Error signing message\n");
        return NULL;
    }
    EVP_MD_CTX_free(md_ctx);
    return sign;
}

// verify signature using public key
int verify_signature(RSA *public_key, unsigned char *message, int message_length, unsigned char *sign, int sign_length) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit(md_ctx, EVP_sha256()) != 1) {
        printf("Error initializing message digest context\n");
        return 0;
    }
    if (EVP_DigestUpdate(md_ctx, message, message_length) != 1) {
        printf("Error updating message digest\n");
        return 0;
    }
    int result = RSA_verify(NID_sha256, md_ctx->md_data, EVP_MD_size(EVP_sha256()), sign, sign_length, public_key);
    if (result != 1) {
        printf("Error verifying signature\n");
    }
    EVP_MD_CTX_free(md_ctx);
    return result;
}

int main() {
    RSA *private_key = generate_key_pair(2048);
    RSA *public_key = RSAPublicKey_dup(private_key);
    unsigned char message[] = "This is a message to be signed";
    int message_length = strlen(message);
    unsigned char *sign = sign_message(private_key, message, message_length);
    int sign_length = RSA_size(private_key);
    int result = verify_signature(public_key, message, message_length, sign, sign_length);
    if (result == 1) {
        printf("Signature verified successfully\n");
    }
    RSA_free(private_key);
    RSA_free(public_key);
    free(sign);
    return 0;
}
