#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H
char* encrypt_xdata(const char* plaintext, long long xtime_ms, const char* xdata_key);
char* decrypt_xdata(const char* xdata, long long xtime_ms, const char* xdata_key);
char* build_encrypted_field(const char* enc_field_key);
#endif
