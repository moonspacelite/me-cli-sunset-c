#ifndef CRYPTO_HELPER_H
#define CRYPTO_HELPER_H
char* make_x_signature(const char* x_api_base_secret, const char* id_token, const char* method, const char* path, long sig_time_sec);
char* make_x_signature_payment(const char* secret, const char* access_token, long sig_time_sec, const char* package_code, const char* token_payment, const char* payment_method, const char* payment_for, const char* path);
#endif
