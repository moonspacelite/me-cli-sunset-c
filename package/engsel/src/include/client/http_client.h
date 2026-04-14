#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H
struct HttpResponse { char* body; long status_code; };
struct HttpResponse* http_post(const char* url, const char* headers[], int header_count, const char* payload);
struct HttpResponse* http_get(const char* url, const char* headers[], int header_count);
void free_http_response(struct HttpResponse* resp);
#endif
