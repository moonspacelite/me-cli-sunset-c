#ifndef CIAM_H
#define CIAM_H
#include "../cJSON.h"
cJSON* get_new_token(const char* base_ciam_url, const char* basic_auth, const char* ua, const char* refresh_token);
cJSON* request_otp(const char* base_ciam_url, const char* basic_auth, const char* ua, const char* number);
cJSON* submit_otp(const char* base_ciam_url, const char* basic_auth, const char* ua, const char* ax_api_sig_key, const char* number, const char* otp);
#endif
