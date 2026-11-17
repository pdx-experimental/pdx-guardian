#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static void b64_encode(const unsigned char *in, size_t len, char *out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, j = 0;
    while (i < len) {
        size_t rem = len - i;
        unsigned int a = in[i++];
        unsigned int b = (rem > 1) ? in[i++] : 0;
        unsigned int c = (rem > 2) ? in[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;
        out[j++] = tbl[(triple >> 18) & 0x3F];
        out[j++] = tbl[(triple >> 12) & 0x3F];
        out[j++] = (rem > 1) ? tbl[(triple >> 6) & 0x3F] : '=';
        out[j++] = (rem > 2) ? tbl[triple & 0x3F] : '=';
    }
    out[j] = '\0';
}

static size_t read_file(const char *path, unsigned char *buf, size_t cap) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t n = fread(buf, 1, cap, fp);
    fclose(fp);
    return n;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int http_req(const char *host, int port, const char *method, const char *path, const char *body, char *resp, size_t resp_cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }

    size_t blen = body ? strlen(body) : 0;
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
                        "%s %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                        method, path, host, port, blen);
    send(fd, hdr, (size_t)hlen, 0);
    if (blen > 0) send(fd, body, blen, 0);

    size_t total = 0;
    ssize_t n;
    while (total + 1 < resp_cap) {
        n = recv(fd, resp + total, resp_cap - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    resp[total] = '\0';
    close(fd);
    if (total == 0) return 0; /* RemoteDisconnected */
    int code = 0;
    sscanf(resp, "HTTP/%*s %d", &code);
    return code;
}

int main(int argc, char **argv) {
    const char *host = "10.0.2.2";
    int port = 18091;
    const char *m_path = "t01_m.bin";
    const char *fw_path = "t01_fw.bin";
    const char *m7_path = "t07_m.bin";
    const char *fw7_path = "t07_fw.bin";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--m1") == 0 && i + 1 < argc) m_path = argv[++i];
        else if (strcmp(argv[i], "--fw1") == 0 && i + 1 < argc) fw_path = argv[++i];
        else if (strcmp(argv[i], "--m7") == 0 && i + 1 < argc) m7_path = argv[++i];
        else if (strcmp(argv[i], "--fw7") == 0 && i + 1 < argc) fw7_path = argv[++i];
    }

    static unsigned char m1[4096], fw1[65536], m7[4096], fw7[65536], fw1_tamper[65536];
    static char m1_b64[8192], fw1_b64[131072], m7_b64[8192], fw7_b64[131072], fw1_tamper_b64[131072];
    static char req[262144], resp[16384], resp_st[16384], resp_rep[16384], resp_b[16384], resp_d[16384], resp_h[4096];

    size_t m1l = read_file(m_path, m1, sizeof(m1));
    size_t fw1l = read_file(fw_path, fw1, sizeof(fw1));
    size_t m7l = read_file(m7_path, m7, sizeof(m7));
    size_t fw7l = read_file(fw7_path, fw7, sizeof(fw7));
    memcpy(fw1_tamper, fw1, fw1l);
    memcpy(fw1_tamper + fw1l, "TAMPER", 6);

    b64_encode(m1, m1l, m1_b64);
    b64_encode(fw1, fw1l, fw1_b64);
    b64_encode(m7, m7l, m7_b64);
    b64_encode(fw7, fw7l, fw7_b64);
    b64_encode(fw1_tamper, fw1l + 6, fw1_tamper_b64);

    struct utsname u;
    uname(&u);
    int h_code = http_req(host, port, "GET", "/health", NULL, resp_h, sizeof(resp_h));

    /* Case A: drop_after_commit */
    double t0 = now_ms();
    snprintf(req, sizeof(req),
             "{\"operation_id\":\"op-wk3-t01-valid-v11\",\"manifest_b64\":\"%s\",\"firmware_b64\":\"%s\",\"drop_mode\":\"drop_after_commit\"}",
             m1_b64, fw1_b64);
    int a_drop = http_req(host, port, "POST", "/submit", req, resp, sizeof(resp));
    int a_st = http_req(host, port, "GET", "/status?op_id=op-wk3-t01-valid-v11", NULL, resp_st, sizeof(resp_st));
    snprintf(req, sizeof(req),
             "{\"operation_id\":\"op-wk3-t01-valid-v11\",\"manifest_b64\":\"%s\",\"firmware_b64\":\"%s\",\"drop_mode\":\"none\"}",
             m1_b64, fw1_b64);
    int a_rep = http_req(host, port, "POST", "/submit", req, resp_rep, sizeof(resp_rep));
    double conv_a = now_ms() - t0;

    /* Case B: drop_before_commit */
    double t1 = now_ms();
    snprintf(req, sizeof(req),
             "{\"operation_id\":\"op-wk3-t07-crash-v12\",\"manifest_b64\":\"%s\",\"firmware_b64\":\"%s\",\"drop_mode\":\"drop_before_commit\"}",
             m7_b64, fw7_b64);
    int b_drop = http_req(host, port, "POST", "/submit", req, resp, sizeof(resp));
    int b_st = http_req(host, port, "GET", "/status?op_id=op-wk3-t07-crash-v12", NULL, resp_b, sizeof(resp_b));
    double conv_b = now_ms() - t1;

    /* Case D: conflicting payload -> 409 */
    snprintf(req, sizeof(req),
             "{\"operation_id\":\"op-wk3-t01-valid-v11\",\"manifest_b64\":\"%s\",\"firmware_b64\":\"%s\",\"drop_mode\":\"none\"}",
             m1_b64, fw1_tamper_b64);
    int d_code = http_req(host, port, "POST", "/submit", req, resp_d, sizeof(resp_d));

    const char *st_body = strstr(resp_st, "\r\n\r\n"); st_body = st_body ? st_body + 4 : "{}";
    const char *rep_body = strstr(resp_rep, "\r\n\r\n"); rep_body = rep_body ? rep_body + 4 : "{}";
    const char *b_body = strstr(resp_b, "\r\n\r\n"); b_body = b_body ? b_body + 4 : "{}";
    const char *d_body = strstr(resp_d, "\r\n\r\n"); d_body = d_body ? d_body + 4 : "{}";
    const char *h_body = strstr(resp_h, "\r\n\r\n"); h_body = h_body ? h_body + 4 : "{}";

    printf("QNX_CLIENT_RESULT {\"client_os\":\"%s\",\"client_release\":\"%s\",\"health_http\":%d,\"target_health\":%s,"
           "\"case_a\":{\"drop_http\":%d,\"status_http\":%d,\"status\":%s,\"replay_http\":%d,\"replay\":%s,\"convergence_ms\":%.2f},"
           "\"case_b\":{\"drop_http\":%d,\"status_http\":%d,\"status\":%s,\"convergence_ms\":%.2f},"
           "\"case_d\":{\"http_status\":%d,\"body\":%s}}\n",
           u.sysname, u.release, h_code, h_body,
           a_drop, a_st, st_body, a_rep, rep_body, conv_a,
           b_drop, b_st, b_body, conv_b,
           d_code, d_body);
    return 0;
}
