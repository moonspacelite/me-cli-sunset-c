#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "../include/service/crypto_aes.h"

static void derive_iv(long long xtime_ms, unsigned char *iv) {
    char xtime_str[64];
    snprintf(xtime_str, sizeof(xtime_str), "%lld", xtime_ms);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)xtime_str, strlen(xtime_str), hash);
    
    char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }
    
    memcpy(iv, hex_hash, 16);
}

static char* base64_urlsafe_encode(const unsigned char* buffer, size_t length) {
    size_t b64_len = 4 * ((length + 2) / 3);
    char* b64_text = malloc(b64_len + 1);
    if (!b64_text) return NULL;
    
    EVP_EncodeBlock((unsigned char*)b64_text, buffer, length);
    
    for (char* p = b64_text; *p != '\0'; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }
    char* eq = strchr(b64_text, '=');
    if (eq) *eq = '\0';
    return b64_text;
}

static unsigned char* base64_urlsafe_decode(const char* b64_text, size_t *out_len) {
    size_t len = strlen(b64_text);
    size_t padded_len = len + (4 - len % 4) % 4; 
    
    char* padded = malloc(padded_len + 1);
    strcpy(padded, b64_text);
    for (size_t i = len; i < padded_len; i++) padded[i] = '=';
    padded[padded_len] = '\0';
    
    for (char* p = padded; *p != '\0'; p++) {
        if (*p == '-') *p = '+';
        else if (*p == '_') *p = '/';
    }
    
    unsigned char* out = malloc(padded_len);
    int decode_len = EVP_DecodeBlock(out, (unsigned char*)padded, padded_len);
    
    int padding_count = 0;
    if (padded_len > 0 && padded[padded_len-1] == '=') padding_count++;
    if (padded_len > 1 && padded[padded_len-2] == '=') padding_count++;
    
    *out_len = decode_len - padding_count;
    free(padded);
    return out;
}

char* encrypt_xdata(const char* plaintext, long long xtime_ms, const char* xdata_key) {
    unsigned char iv[16];
    derive_iv(xtime_ms, iv);
    
    size_t pt_len = strlen(plaintext);
    size_t pad = 16 - (pt_len % 16);
    size_t padded_len = pt_len + pad;
    unsigned char* padded = malloc(padded_len);
    if (!padded) return NULL;
    memcpy(padded, plaintext, pt_len);
    for (size_t i = pt_len; i < padded_len; i++) padded[i] = (unsigned char)pad;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)xdata_key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    int len;
    int ciphertext_len;
    unsigned char *ciphertext = malloc(padded_len + 16);
    if (!ciphertext) {
        free(padded);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    EVP_EncryptUpdate(ctx, ciphertext, &len, padded, padded_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    free(padded);
    
    char* final_b64 = base64_urlsafe_encode(ciphertext, ciphertext_len);
    free(ciphertext);
    return final_b64;
}

char* decrypt_xdata(const char* xdata, long long xtime_ms, const char* xdata_key) {
    unsigned char iv[16];
    derive_iv(xtime_ms, iv);
    
    size_t ct_len;
    unsigned char* ct = base64_urlsafe_decode(xdata, &ct_len);
    if (!ct) return NULL;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)xdata_key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    unsigned char *plaintext = malloc(ct_len + 16);
    if (!plaintext) {
        free(ct);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int len;
    int pt_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ct, ct_len) != 1) {
        free(ct); free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    pt_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        free(ct); free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    pt_len += len;
    
    if (pt_len > 0) {
        unsigned char pad = plaintext[pt_len - 1];
        if (pad > 0 && pad <= 16) {
            int valid = 1;
            for (int i = pt_len - pad; i < pt_len; i++) {
                if (plaintext[i] != pad) { valid = 0; break; }
            }
            if (valid) pt_len -= pad;
        }
    }
    plaintext[pt_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    free(ct);
    
    return (char*)plaintext;
}

char* build_encrypted_field(const char* enc_field_key) {
    unsigned char iv_bytes[8];
    for(int i=0; i<8; i++) iv_bytes[i] = random() % 256;
    char iv_hex[17];
    for(int i=0; i<8; i++) sprintf(&iv_hex[i*2], "%02x", iv_bytes[i]);

    unsigned char pt[16];
    for(int i=0; i<16; i++) pt[i] = 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char*)enc_field_key, (unsigned char*)iv_hex);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char ct[16]; int len;
    EVP_EncryptUpdate(ctx, ct, &len, pt, 16);
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    char* b64 = base64_urlsafe_encode(ct, 16);
    char* result = malloc(strlen(b64) + 17);
    sprintf(result, "%s%s", b64, iv_hex);
    free(b64);
    return result;
}
