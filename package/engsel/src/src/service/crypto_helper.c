#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "../include/service/crypto_helper.h"

char* make_x_signature(const char* x_api_base_secret, const char* id_token, const char* method, const char* path, long sig_time_sec) {
    // Buffer untuk key: "{X_API_BASE_SECRET};{id_token};{method};{path};{sig_time_sec}"
    size_t key_len = snprintf(NULL, 0, "%s;%s;%s;%s;%ld", x_api_base_secret, id_token, method, path, sig_time_sec);
    char* key_str = malloc(key_len + 1);
    if (!key_str) return NULL;
    snprintf(key_str, key_len + 1, "%s;%s;%s;%s;%ld", x_api_base_secret, id_token, method, path, sig_time_sec);

    // Buffer untuk msg: "{id_token};{sig_time_sec};"
    size_t msg_len = snprintf(NULL, 0, "%s;%ld;", id_token, sig_time_sec);
    char* msg = malloc(msg_len + 1);
    if (!msg) {
        free(key_str);
        return NULL;
    }
    snprintf(msg, msg_len + 1, "%s;%ld;", id_token, sig_time_sec);

    // Proses HMAC SHA512 menggunakan OpenSSL
    unsigned char* result;
    unsigned int len = 64; // SHA512 menghasilkan 64 bytes
    
    result = HMAC(EVP_sha512(), key_str, strlen(key_str), (unsigned char*)msg, strlen(msg), NULL, &len);

    // Convert hasil hash dari byte ke hex string
    char* hex_result = malloc((len * 2) + 1);
    if (hex_result) {
        for (unsigned int i = 0; i < len; i++) {
            sprintf(&hex_result[i * 2], "%02x", (unsigned int)result[i]);
        }
    }

    // Bebaskan memori buffer yang sudah tidak terpakai
    free(key_str);
    free(msg);

    return hex_result;
}

// Tambahkan make_x_signature_payment di paling bawah file
char* make_x_signature_payment(const char* secret, const char* access_token, long sig_time_sec, const char* package_code, const char* token_payment, const char* payment_method, const char* payment_for, const char* path) {
    char key_str[1024]; snprintf(key_str, sizeof(key_str), "%s;%ld#ae-hei_9Tee6he+Ik3Gais5=;POST;%s;%ld", secret, sig_time_sec, path, sig_time_sec);
    char msg[2048]; snprintf(msg, sizeof(msg), "%s;%s;%ld;%s;%s;%s;", access_token, token_payment, sig_time_sec, payment_for, payment_method, package_code);

    unsigned char* result; unsigned int len = 64;
    result = HMAC(EVP_sha512(), key_str, strlen(key_str), (unsigned char*)msg, strlen(msg), NULL, &len);

    char* hex_result = malloc((len * 2) + 1);
    if (hex_result) { for (unsigned int i = 0; i < len; i++) sprintf(&hex_result[i * 2], "%02x", result[i]); }
    return hex_result;
}
