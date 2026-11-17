#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define MAX_OPS 256
#define MAX_REQ_BYTES (1024 * 1024)

typedef struct {
    char op_id[128];
    char digest[65];
    int target_version;
    char slot[16];
    int seq;
} committed_op_t;

typedef struct {
    int active_version;
    char active_slot[16];
    int last_seq;
    int write_count;
    int op_count;
    committed_op_t ops[MAX_OPS];
} target_state_t;

static char g_state_dir[256] = "/tmp/pdx_qnx_state";
static char g_gate_bin[256] = "./oci_portable_gate_qnx.elf";
static char g_pubkey_hex[128] = "";
static target_state_t g_state;

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_cap) {
    size_t out = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out < dst_cap) dst[out++] = (uint8_t)((acc >> bits) & 0xFFU);
        }
    }
    return out;
}

static void sha256_two(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, char out_hex[65]) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, a, alen);
    SHA256_Update(&ctx, b, blen);
    SHA256_Final(digest, &ctx);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out_hex[2 * i] = hex[(digest[i] >> 4) & 0xF];
        out_hex[2 * i + 1] = hex[digest[i] & 0xF];
    }
    out_hex[64] = '\0';
}

static int json_get_str(const char *json, const char *key, char *out, size_t cap) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (*p == '"') ? 0 : -1;
}

static int json_get_int(const char *json, const char *key, int *out) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n') p++;
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        *out = atoi(p);
        return 0;
    }
    return -1;
}

static int write_file_sync(const char *path, const uint8_t *buf, size_t len) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void state_init_default(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.active_version = 10;
    snprintf(g_state.active_slot, sizeof(g_state.active_slot), "SLOT_A");
    g_state.last_seq = 0;
    g_state.write_count = 0;
    g_state.op_count = 0;
}

static int state_save_ex(int inject_err) {
    char path[512];
    char tmp[512];
    snprintf(path, sizeof(path), "%s/target_state.db", g_state_dir);
    snprintf(tmp, sizeof(tmp), "%s/target_state.db.tmp", g_state_dir);
    FILE *fp = fopen(tmp, "w");
    if (!fp) return -1;
    int io_err = 0;
    if (fprintf(fp, "META %d %s %d %d\n",
                g_state.active_version, g_state.active_slot, g_state.last_seq, g_state.write_count) < 0) {
        io_err = 1;
    }
    for (int i = 0; !io_err && i < g_state.op_count; i++) {
        if (fprintf(fp, "OP %s %s %d %s %d\n",
                    g_state.ops[i].op_id,
                    g_state.ops[i].digest,
                    g_state.ops[i].target_version,
                    g_state.ops[i].slot,
                    g_state.ops[i].seq) < 0) {
            io_err = 1;
        }
    }
    if (fflush(fp) != 0) io_err = 1;
    if (fsync(fileno(fp)) != 0) io_err = 1;
    if (fclose(fp) != 0) io_err = 1;
    if (io_err || inject_err) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int state_save(void) {
    return state_save_ex(0);
}

static void state_load_or_init(void) {
    mkdir(g_state_dir, 0755);
    char path[512];
    snprintf(path, sizeof(path), "%s/target_state.db", g_state_dir);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        state_init_default();
        state_save();
        return;
    }
    state_init_default();
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "META ", 5) == 0) {
            sscanf(line + 5, "%d %15s %d %d",
                   &g_state.active_version, g_state.active_slot, &g_state.last_seq, &g_state.write_count);
        } else if (strncmp(line, "OP ", 3) == 0 && g_state.op_count < MAX_OPS) {
            committed_op_t *op = &g_state.ops[g_state.op_count];
            if (sscanf(line + 3, "%127s %64s %d %15s %d",
                       op->op_id, op->digest, &op->target_version, op->slot, &op->seq) == 5) {
                g_state.op_count++;
            }
        }
    }
    fclose(fp);
}

static committed_op_t *find_op(const char *op_id) {
    for (int i = 0; i < g_state.op_count; i++) {
        if (strcmp(g_state.ops[i].op_id, op_id) == 0) return &g_state.ops[i];
    }
    return NULL;
}

static void send_json(int fd, int code, const char *status, const char *body) {
    char hdr[512];
    size_t blen = strlen(body);
    int hlen = snprintf(hdr, sizeof(hdr),
                        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                        code, status, blen);
    send(fd, hdr, (size_t)hlen, 0);
    send(fd, body, blen, 0);
    shutdown(fd, SHUT_WR);
}

static size_t parse_content_length(const char *req, const char *hdr_end) {
    for (const char *p = req; p < hdr_end; p++) {
        if ((p == req || p[-1] == '\n') && strncasecmp(p, "content-length:", 15) == 0) {
            return (size_t)strtoul(p + 15, NULL, 10);
        }
    }
    return 0;
}

static void handle_client(int cfd) {
    char *req = (char *)malloc(MAX_REQ_BYTES + 1);
    if (!req) { close(cfd); return; }
    size_t total = 0;
    ssize_t n;
    size_t content_len = 0;
    char *hdr_end = NULL;

    while (total < MAX_REQ_BYTES) {
        n = recv(cfd, req + total, MAX_REQ_BYTES - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        req[total] = '\0';
        if (!hdr_end) {
            hdr_end = strstr(req, "\r\n\r\n");
            if (hdr_end) content_len = parse_content_length(req, hdr_end);
        }
        if (hdr_end && (total - (size_t)((hdr_end + 4) - req)) >= content_len) break;
    }

    if (strncmp(req, "GET /health", 11) == 0) {
        struct utsname u;
        uname(&u);
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"status\":\"ok\",\"sysname\":\"%s\",\"machine\":\"%s\",\"release\":\"%s\",\"pid\":%d,\"active_version\":%d,\"active_slot\":\"%s\",\"write_count\":%d}",
                 u.sysname, u.machine, u.release, (int)getpid(), g_state.active_version, g_state.active_slot, g_state.write_count);
        send_json(cfd, 200, "OK", body);
        free(req);
        close(cfd);
        return;
    }

    if (strncmp(req, "GET /status", 11) == 0) {
        char op_id[128] = "";
        const char *q = strstr(req, "op_id=");
        if (q) {
            q += 6;
            size_t i = 0;
            while (q[i] && q[i] != ' ' && q[i] != '&' && q[i] != '\r' && i + 1 < sizeof(op_id)) {
                op_id[i] = q[i];
                i++;
            }
            op_id[i] = '\0';
        }
        committed_op_t *found = op_id[0] ? find_op(op_id) : NULL;
        char body[1024];
        if (found) {
            snprintf(body, sizeof(body),
                     "{\"active_version\":%d,\"active_slot\":\"%s\",\"last_sequence_id\":%d,\"write_count\":%d,\"committed\":true,"
                     "\"receipt\":{\"operation_id\":\"%s\",\"decision\":\"ALLOW\",\"slot_status\":\"STAGED_AND_ACTIVATED_%s\",\"target_version\":%d,\"sequence_id\":%d,\"payload_sha256\":\"%s\"}}",
                     g_state.active_version, g_state.active_slot, g_state.last_seq, g_state.write_count,
                     found->op_id, found->slot, found->target_version, found->seq, found->digest);
        } else {
            snprintf(body, sizeof(body),
                     "{\"active_version\":%d,\"active_slot\":\"%s\",\"last_sequence_id\":%d,\"write_count\":%d,\"committed\":false,\"receipt\":null}",
                     g_state.active_version, g_state.active_slot, g_state.last_seq, g_state.write_count);
        }
        send_json(cfd, 200, "OK", body);
        free(req);
        close(cfd);
        return;
    }

    if (strncmp(req, "POST /submit", 12) == 0 && hdr_end) {
        const char *body = hdr_end + 4;
        char op_hint[128] = "";
        char drop_mode[64] = "none";
        static char m_b64[65536];
        static char fw_b64[524288];
        static uint8_t m_bin[49152];
        static uint8_t fw_bin[393288];

        json_get_str(body, "operation_id", op_hint, sizeof(op_hint));
        json_get_str(body, "drop_mode", drop_mode, sizeof(drop_mode));
        if (json_get_str(body, "manifest_b64", m_b64, sizeof(m_b64)) != 0 ||
            json_get_str(body, "firmware_b64", fw_b64, sizeof(fw_b64)) != 0) {
            send_json(cfd, 400, "Bad Request", "{\"error\":\"missing_payload\"}");
            free(req);
            close(cfd);
            return;
        }

        if (strcmp(drop_mode, "drop_before_commit") == 0) {
            free(req);
            close(cfd);
            return;
        }

        size_t m_len = b64_decode(m_b64, strlen(m_b64), m_bin, sizeof(m_bin));
        size_t fw_len = b64_decode(fw_b64, strlen(fw_b64), fw_bin, sizeof(fw_bin));
        char digest[65];
        sha256_two(m_bin, m_len, fw_bin, fw_len, digest);

        committed_op_t *existing = find_op(op_hint);
        if (existing) {
            if (strcmp(existing->digest, digest) != 0) {
                send_json(cfd, 409, "Conflict", "{\"error\":\"operation_id_payload_mismatch\"}");
            } else {
                char resp[512];
                snprintf(resp, sizeof(resp),
                         "{\"operation_id\":\"%s\",\"decision\":\"ALLOW\",\"idempotent_replay\":true,\"target_version\":%d,\"slot_status\":\"STAGED_AND_ACTIVATED_%s\",\"write_count\":%d}",
                         existing->op_id, existing->target_version, existing->slot, g_state.write_count);
                send_json(cfd, 200, "OK", resp);
            }
            free(req);
            close(cfd);
            return;
        }

        char m_path[512], f_path[512], cmd[1024];
        snprintf(m_path, sizeof(m_path), "%s/req_manifest.bin", g_state_dir);
        snprintf(f_path, sizeof(f_path), "%s/req_firmware.bin", g_state_dir);
        if (write_file_sync(m_path, m_bin, m_len) != 0 ||
            write_file_sync(f_path, fw_bin, fw_len) != 0) {
            send_json(cfd, 500, "Internal Server Error", "{\"error\":\"persist_failed\",\"committed\":false}");
            free(req);
            close(cfd);
            return;
        }

        snprintf(cmd, sizeof(cmd),
                 "%s --manifest %s --firmware %s --pubkey-hex %s --active-version %d --last-seq %d",
                 g_gate_bin, m_path, f_path, g_pubkey_hex, g_state.active_version, g_state.last_seq);
        FILE *pp = popen(cmd, "r");
        char gate_out[1024] = "";
        if (pp) {
            fgets(gate_out, sizeof(gate_out), pp);
            pclose(pp);
        }

        char decision[64] = "";
        char gate_op[128] = "";
        int target_ver = 0;
        int seq_id = 0;
        json_get_str(gate_out, "decision", decision, sizeof(decision));
        json_get_str(gate_out, "operation_id", gate_op, sizeof(gate_op));
        json_get_int(gate_out, "target_version", &target_ver);
        json_get_int(gate_out, "sequence_id", &seq_id);

        if (strcmp(decision, "ALLOW") == 0 && g_state.op_count < MAX_OPS) {
            const char *next_slot = (strcmp(g_state.active_slot, "SLOT_A") == 0) ? "SLOT_B" : "SLOT_A";
            char slot_fw[512];
            snprintf(slot_fw, sizeof(slot_fw), "%s/slot_%s_fw.bin", g_state_dir, next_slot);
            if (strcmp(drop_mode, "inject_persist_error") == 0 ||
                write_file_sync(slot_fw, fw_bin, fw_len) != 0) {
                send_json(cfd, 500, "Internal Server Error", "{\"error\":\"persist_failed\",\"committed\":false}");
                free(req);
                close(cfd);
                return;
            }

            target_state_t prev_state = g_state;
            g_state.active_version = target_ver;
            snprintf(g_state.active_slot, sizeof(g_state.active_slot), "%s", next_slot);
            g_state.last_seq = seq_id;
            g_state.write_count += 1;

            committed_op_t *rec = &g_state.ops[g_state.op_count++];
            snprintf(rec->op_id, sizeof(rec->op_id), "%s", gate_op[0] ? gate_op : op_hint);
            snprintf(rec->digest, sizeof(rec->digest), "%s", digest);
            rec->target_version = target_ver;
            snprintf(rec->slot, sizeof(rec->slot), "%s", next_slot);
            rec->seq = seq_id;
            if (state_save_ex(strcmp(drop_mode, "inject_state_save_error") == 0) != 0) {
                g_state = prev_state;
                send_json(cfd, 500, "Internal Server Error", "{\"error\":\"persist_failed\",\"committed\":false}");
                free(req);
                close(cfd);
                return;
            }

            if (strcmp(drop_mode, "drop_after_commit") == 0) {
                free(req);
                close(cfd);
                return;
            }
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"operation_id\":\"%s\",\"decision\":\"ALLOW\",\"target_version\":%d,\"slot_status\":\"STAGED_AND_ACTIVATED_%s\",\"write_count\":%d}",
                     rec->op_id, rec->target_version, rec->slot, g_state.write_count);
            send_json(cfd, 200, "OK", resp);
        } else {
            send_json(cfd, 403, "Forbidden", gate_out[0] ? gate_out : "{\"decision\":\"DENY\"}");
        }
        free(req);
        close(cfd);
        return;
    }

    send_json(cfd, 404, "Not Found", "{\"error\":\"not_found\"}");
    free(req);
    close(cfd);
}

int main(int argc, char **argv) {
    int port = 8080;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) snprintf(g_state_dir, sizeof(g_state_dir), "%s", argv[++i]);
        else if (strcmp(argv[i], "--gate-bin") == 0 && i + 1 < argc) snprintf(g_gate_bin, sizeof(g_gate_bin), "%s", argv[++i]);
        else if (strcmp(argv[i], "--pubkey-hex") == 0 && i + 1 < argc) snprintf(g_pubkey_hex, sizeof(g_pubkey_hex), "%s", argv[++i]);
    }
    if (!g_pubkey_hex[0]) {
        fprintf(stderr, "Missing --pubkey-hex\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    state_load_or_init();

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(sfd, 16) != 0) {
        perror("bind/listen");
        return 1;
    }
    printf("QNX_TARGET_READY port=%d active_ver=%d active_slot=%s write_count=%d\n",
           port, g_state.active_version, g_state.active_slot, g_state.write_count);
    fflush(stdout);

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd >= 0) handle_client(cfd);
    }
    return 0;
}
