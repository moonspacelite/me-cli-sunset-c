#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "../include/client/http_client.h"

static CURL *shared_curl = NULL;
struct MemoryStruct { char *memory; size_t size; };

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) return 0;
    mem->memory = ptr; memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize; mem->memory[mem->size] = 0;
    return realsize;
}

static CURL* get_curl_handle() {
    if (!shared_curl) { curl_global_init(CURL_GLOBAL_ALL); shared_curl = curl_easy_init(); }
    else { curl_easy_reset(shared_curl); }
    return shared_curl;
}

struct HttpResponse* http_post(const char* url, const char* headers[], int header_count, const char* payload) {
    CURL *curl = get_curl_handle();
    struct HttpResponse* response = malloc(sizeof(struct HttpResponse));
    response->body = NULL; response->status_code = 0;
    struct MemoryStruct chunk; chunk.memory = malloc(1); chunk.size = 0;
    if(curl) {
        struct curl_slist *chunk_headers = NULL;
        for(int i = 0; i < header_count; i++) chunk_headers = curl_slist_append(chunk_headers, headers[i]);
        curl_easy_setopt(curl, CURLOPT_URL, url); curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk_headers); curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk); curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        CURLcode res = curl_easy_perform(curl);
        if(res == CURLE_OK) { curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code); response->body = chunk.memory; }
        else { free(chunk.memory); }
        curl_slist_free_all(chunk_headers);
    }
    return response;
}

struct HttpResponse* http_get(const char* url, const char* headers[], int header_count) {
    CURL *curl = get_curl_handle();
    struct HttpResponse* response = malloc(sizeof(struct HttpResponse));
    response->body = NULL; response->status_code = 0;
    struct MemoryStruct chunk; chunk.memory = malloc(1); chunk.size = 0;
    if(curl) {
        struct curl_slist *chunk_headers = NULL;
        for(int i = 0; i < header_count; i++) chunk_headers = curl_slist_append(chunk_headers, headers[i]);
        curl_easy_setopt(curl, CURLOPT_URL, url); curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk_headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        CURLcode res = curl_easy_perform(curl);
        if(res == CURLE_OK) { curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code); response->body = chunk.memory; }
        else { free(chunk.memory); }
        curl_slist_free_all(chunk_headers);
    }
    return response;
}

void free_http_response(struct HttpResponse* resp) { if(resp) { if(resp->body) free(resp->body); free(resp); } }
