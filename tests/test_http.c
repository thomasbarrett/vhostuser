#include <src/http.c>
#include <src/log.c>

#include <assert.h>
#include <string.h>

void test_http_reason_phrase(void) {
    assert(strcmp(http_reason_phrase(200), "OK") == 0);
    assert(strcmp(http_reason_phrase(400), "Bad Request") == 0);
    assert(strcmp(http_reason_phrase(404), "Not Found") == 0);
}

void test_parse_whitespace(void) {
    const char *buf1 = "   ";
    assert(parse_whitespace(buf1, strlen(buf1)) == 3);

    const char *buf2 = "  #";
    assert(parse_whitespace(buf2, strlen(buf2)) == 2);

    const char *buf3 = "";
    assert(parse_whitespace(buf3, strlen(buf3)) == 0);
}

void test_parse_string(void) {
    const char *buf1 = "hello world";
    const char *str1 = "hello";
    assert(parse_string(buf1, strlen(buf1), str1) == strlen(str1));
    
    const char *str2 = "hello world!";
    assert(parse_string(buf1, strlen(buf1), str2) == PARSE_INCOMPLETE);

    const char *str3 = "goodbye";
    assert(parse_string(buf1, strlen(buf1), str3) == PARSE_ERROR);

    const char *str4 = "hello world";
    assert(parse_string(buf1, strlen(buf1), str4) == strlen(str4));
}

void test_parse_char(void) {
    const char *buf1 = "hello world";
    assert(parse_char(buf1, strlen(buf1), 'h') == 1);
    assert(parse_char(buf1, strlen(buf1), 'H') == PARSE_ERROR);
    
    const char *buf2 = "";
    assert(parse_char(buf2, strlen(buf2), 'h') == PARSE_INCOMPLETE);
}

void test_parse_token(void) {
    char res[16] = {0};
    
    const char *buf1 = "hello world";
    assert(parse_token(buf1, strlen(buf1), " ", res, sizeof(res)) == strlen("hello"));

    const char *buf2 = "hello\nworld";
    assert(parse_token(buf2, strlen(buf2), " \r\n", res, sizeof(res)) == strlen("hello"));
}

void test_parse_request_line(void) {
    http_request_t req = {0};

    const char *buf1 = "GET /metrics HTTP/1.1\r\n";
    assert(parse_request_line(buf1, strlen(buf1), &req) == strlen(buf1));
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.uri, "/metrics") == 0);
    assert(strcmp(req.version, "HTTP/1.1") == 0);

    memset(&req, 0, sizeof(http_request_t));
    const char *buf2 = "GET /metrics HTTP/1.1";
    assert(parse_request_line(buf2, strlen(buf2), &req) == PARSE_INCOMPLETE);

    memset(&req, 0, sizeof(http_request_t));
    const char *buf3 = "GET /metrics HTTP/1.1\n";
    assert(parse_request_line(buf3, strlen(buf3), &req) == PARSE_ERROR);
}

void test_parse_header(void) {
    http_header_t header = {0};

    const char *buf1 = "Foo: Bar\r\n";
    assert(parse_header(buf1, strlen(buf1), &header) == strlen(buf1));
    assert(strcmp(header.name, "Foo") == 0);
    assert(strcmp(header.value, "Bar") == 0);

    memset(&header, 0, sizeof(http_header_t));   
    const char *buf2 = "Foo: Bar";
    assert(parse_header(buf2, strlen(buf2), &header) == PARSE_INCOMPLETE);

    memset(&header, 0, sizeof(http_header_t));   
    const char *buf3 = "Foo\r\n";
    assert(parse_header(buf3, strlen(buf3), &header) == PARSE_ERROR);
}

void test_parse_request(void) {
    http_request_t req = {0};

    const char *buf1 = "GET /metrics HTTP/1.1\r\n\r\n";
    assert(parse_request(buf1, strlen(buf1), &req) == strlen(buf1));
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.uri, "/metrics") == 0);
    assert(strcmp(req.version, "HTTP/1.1") == 0);
    assert(req.headers_len == 0);

    memset(&req, 0, sizeof(http_request_t));   
    const char *buf2 = "GET /metrics HTTP/1.1\r\n";
    assert(parse_request(buf2, strlen(buf2), &req) == PARSE_INCOMPLETE);

    memset(&req, 0, sizeof(http_request_t));   
    const char *buf3 = "GET /metrics HTTP/1.1\r\nAuthorization: Bearer foo\r\n\r\n";
    assert(parse_request(buf3, strlen(buf3), &req) == strlen(buf3));
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.uri, "/metrics") == 0);
    assert(strcmp(req.version, "HTTP/1.1") == 0);
    assert(req.headers_len == 1);
    assert(strcmp(req.headers[0].name, "Authorization") == 0);
    assert(strcmp(req.headers[0].value, "Bearer foo") == 0);

    memset(&req, 0, sizeof(http_request_t));   
    const char *buf4 = "GET /metrics HTTP/1.1\r\nAuthorization: Bearer foo\r\n";
    assert(parse_request(buf4, strlen(buf4), &req) == PARSE_INCOMPLETE);
}

int main(void) {
    test_http_reason_phrase();
    test_parse_whitespace();
    test_parse_string();
    test_parse_char();
    test_parse_token();
    test_parse_request_line();
    test_parse_header();
    test_parse_request();
}
