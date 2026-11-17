/*
 * Native QNX 8.0 Vehicle Host Worker (qnx_veh_host.elf)
 * Runs inside QNX Neutrino 8.0.0 (x86pc QEMU):
 * - Receives & sends DrivingIntentV2 packets over real UDP sockets
 * - Serves batched STEP_BATCH / GET_SUMMARY / GET_LOGS / SHUTDOWN over TCP (4-byte length-prefixed JSON)
 * - Executes Guardian safety arbiter, physical stopping distance, and cooperative intent logic in native C
 */

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static inline int64_t mono_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)(ts.tv_nsec / 1000L);
}

#define MAX_VEHS 640
#define MAX_PEERS 640
#define MAX_LEADERS 64
#define MAX_VIS 48
#define TTL_MS_DEFAULT 500
#define BROADCAST_PERIOD_MS 200
#define OCCLUSION_VIS_CLEAR_M 25.0
#define REACT_TIME_S 0.5
#define MAX_DECEL_MPS2 4.5
#define STOP_MARGIN_M 2.0

typedef struct {
    char vehicle_id[32];
    char zone_id[16];
    int seq;
    int issued_at_sim_ms;
    int ttl_ms;
    char incoming_edge[32];
    int is_left_turn;
    char cz[8];
    int conflict_entry_sim_ms;
    int conflict_exit_sim_ms;
    int valid;
} peer_intent_t;

typedef struct {
    char vehicle_id[32];
    char zone_id[16];
    int silent;
    int seq;
    int last_bcast_ms;
    int last_seen_seq[MAX_VEHS];
    peer_intent_t peer_intents[MAX_VEHS];
    int degraded_before_restore;
    int partition_affected;
    int still_approaching_at_restore;
    int intent_ready_ms;   /* -1 if unset */
    int coop_recovered_ms; /* -1 if unset */
    int last_blocked_ms;   /* -1 if unset */
    int stale_dropped;
    int stale_overwrites;
    int expired_rx;
    int tx_count;
} veh_node_t;

typedef struct {
    char vehicle_id[32];
    char edge[32];
    char cz[8];
    int is_left_turn;
    double speed_mps;
    double d_to_cz_m;
    int in_cz;
} vis_peer_t;

static veh_node_t g_nodes[MAX_VEHS];
static int g_num_nodes = 0;
static char g_host_id[64] = "qnx-zone-a";
static char g_mode[32] = "cooperative";
static char g_tx_log_path[256];
static char g_rx_log_path[256];
static FILE *g_tx_fp = NULL;
static FILE *g_rx_fp = NULL;

static int g_rx_sock = -1;
static int g_tx_sock = -1;
static struct sockaddr_in g_gw_addr;
static pthread_mutex_t g_rx_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_stop = 0;

#define RX_RING_CAP 4096
static peer_intent_t g_rx_ring[RX_RING_CAP];
static char g_rx_pkt_ids[RX_RING_CAP][48];
static int g_rx_head = 0;
static int g_rx_tail = 0;
static int g_rx_count = 0;
static int g_rx_q_max = 0;

static int veh_index(const char *vid) {
    /* Fast path for veh-NNN */
    if (strncmp(vid, "veh-", 4) == 0 && vid[4] >= '0' && vid[4] <= '9') {
        int idx = atoi(vid + 4);
        if (idx >= 0 && idx < MAX_VEHS) return idx;
    }
    return -1;
}

static veh_node_t *find_node(const char *vid) {
    for (int i = 0; i < g_num_nodes; i++) {
        if (strcmp(g_nodes[i].vehicle_id, vid) == 0) return &g_nodes[i];
    }
    return NULL;
}

/* Minimal JSON field extractors */
static int json_get_str(const char *obj, const char *end, const char *key, char *out, size_t out_sz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = obj;
    while (p < end) {
        p = strstr(p, pat);
        if (!p || p >= end) return -1;
        p += strlen(pat);
        while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) p++;
        if (p < end && *p == '"') {
            p++;
            const char *q = p;
            while (q < end && *q != '"') q++;
            size_t len = (size_t)(q - p);
            if (len >= out_sz) len = out_sz - 1;
            memcpy(out, p, len);
            out[len] = '\0';
            return 0;
        }
    }
    return -1;
}

static int json_get_int(const char *obj, const char *end, const char *key, int *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(obj, pat);
    if (!p || p >= end) return -1;
    p += strlen(pat);
    while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (p < end && (*p == '-' || (*p >= '0' && *p <= '9'))) {
        *out = atoi(p);
        return 0;
    }
    return -1;
}

static int json_get_double(const char *obj, const char *end, const char *key, double *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(obj, pat);
    if (!p || p >= end) return -1;
    p += strlen(pat);
    while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (p < end && (*p == '-' || (*p >= '0' && *p <= '9'))) {
        *out = atof(p);
        return 0;
    }
    return -1;
}

static int json_get_bool(const char *obj, const char *end, const char *key, int *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(obj, pat);
    if (!p || p >= end) return -1;
    p += strlen(pat);
    while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (p + 4 <= end && strncmp(p, "true", 4) == 0) { *out = 1; return 0; }
    if (p + 5 <= end && strncmp(p, "false", 5) == 0) { *out = 0; return 0; }
    if (p < end && (*p == '0' || *p == '1')) { *out = (*p == '1'); return 0; }
    return -1;
}

static const char *find_matching_brace(const char *open_p, const char *limit) {
    int depth = 0;
    int in_str = 0;
    for (const char *p = open_p; p < limit; p++) {
        if (*p == '"' && (p == open_p || *(p - 1) != '\\')) in_str = !in_str;
        if (in_str) continue;
        if (*p == '{' || *p == '[') depth++;
        else if (*p == '}' || *p == ']') {
            depth--;
            if (depth == 0) return p;
        }
    }
    return NULL;
}

static int is_ew_edge(const char *e) {
    return (strcmp(e, "w_to_j1") == 0 || strcmp(e, "j2_to_j1") == 0 ||
            strcmp(e, "j1_to_j2") == 0 || strcmp(e, "j3_to_j2") == 0 ||
            strcmp(e, "j2_to_j3") == 0 || strcmp(e, "e_to_j3") == 0);
}

static int movements_conflict_cz(const char *cz1, const char *e1, int l1,
                                 const char *cz2, const char *e2, int l2) {
    if (strcmp(cz1, "none") == 0 || strcmp(cz1, cz2) != 0) return 0;
    if (strcmp(e1, e2) == 0) return 0;
    if (is_ew_edge(e1) != is_ew_edge(e2)) return 1;
    return (l1 || l2) ? 1 : 0;
}

static int is_priority_row(const char *e, int is_left) {
    if (is_left) return 0;
    return is_ew_edge(e);
}

static int has_higher_row(const char *v1, const char *e1, int l1, int t1,
                          const char *v2, const char *e2, int l2, int t2) {
    int r1 = is_priority_row(e1, l1);
    int r2 = is_priority_row(e2, l2);
    if (r1 != r2) return r1 > r2;
    if (abs(t1 - t2) >= 250) return t1 < t2;
    return strcmp(v1, v2) < 0;
}

static double required_stopping_distance_m(double v) {
    if (v <= 0.0) return STOP_MARGIN_M;
    return v * REACT_TIME_S + (v * v) / (2.0 * MAX_DECEL_MPS2) + STOP_MARGIN_M;
}

static double max_safe_approach_speed_mps(double d_avail) {
    double d_net = d_avail - STOP_MARGIN_M;
    if (d_net <= 0.0) return 0.0;
    double a = MAX_DECEL_MPS2;
    double tr = REACT_TIME_S;
    double disc = (a * tr) * (a * tr) + 2.0 * a * d_net;
    double v = -a * tr + sqrt(disc);
    if (v < 0.0) v = 0.0;
    if (v > 13.89) v = 13.89;
    return v;
}

static int time_windows_overlap(int s1, int e1, int s2, int e2) {
    int buf = 400;
    return (s1 <= e2 + buf) && (s2 <= e1 + buf);
}

static void *rx_thread_fn(void *arg) {
    (void)arg;
    char buf[4096];
    while (!g_stop) {
        ssize_t n = recvfrom(g_rx_sock, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            break;
        }
        buf[n] = '\0';
        const char *end = buf + n;
        peer_intent_t pi;
        memset(&pi, 0, sizeof(pi));
        pi.ttl_ms = TTL_MS_DEFAULT;
        pi.valid = 1;
        if (json_get_str(buf, end, "vehicle_id", pi.vehicle_id, sizeof(pi.vehicle_id)) != 0) continue;
        json_get_str(buf, end, "zone_id", pi.zone_id, sizeof(pi.zone_id));
        json_get_int(buf, end, "seq", &pi.seq);
        json_get_int(buf, end, "issued_at_sim_ms", &pi.issued_at_sim_ms);
        json_get_int(buf, end, "ttl_ms", &pi.ttl_ms);
        json_get_str(buf, end, "incoming_edge", pi.incoming_edge, sizeof(pi.incoming_edge));
        json_get_bool(buf, end, "is_left_turn", &pi.is_left_turn);
        char cz_full[16] = "";
        json_get_str(buf, end, "conflict_zone_id", cz_full, sizeof(cz_full));
        char *us = strchr(cz_full, '_');
        if (us) *us = '\0';
        snprintf(pi.cz, sizeof(pi.cz), "%s", cz_full);
        json_get_int(buf, end, "conflict_entry_sim_ms", &pi.conflict_entry_sim_ms);
        json_get_int(buf, end, "conflict_exit_sim_ms", &pi.conflict_exit_sim_ms);
        char pkt_id[48] = "";
        json_get_str(buf, end, "packet_id", pkt_id, sizeof(pkt_id));

        pthread_mutex_lock(&g_rx_lock);
        if (g_rx_count < RX_RING_CAP) {
            g_rx_ring[g_rx_tail] = pi;
            snprintf(g_rx_pkt_ids[g_rx_tail], sizeof(g_rx_pkt_ids[0]), "%s", pkt_id);
            g_rx_tail = (g_rx_tail + 1) % RX_RING_CAP;
            g_rx_count++;
            if (g_rx_count > g_rx_q_max) g_rx_q_max = g_rx_count;
        }
        pthread_mutex_unlock(&g_rx_lock);
    }
    return NULL;
}

static void drain_rx(int sim_ms) {
    pthread_mutex_lock(&g_rx_lock);
    while (g_rx_count > 0) {
        peer_intent_t pi = g_rx_ring[g_rx_head];
        char pkt_id[48];
        snprintf(pkt_id, sizeof(pkt_id), "%s", g_rx_pkt_ids[g_rx_head]);
        g_rx_head = (g_rx_head + 1) % RX_RING_CAP;
        g_rx_count--;
        pthread_mutex_unlock(&g_rx_lock);

        int s_idx = veh_index(pi.vehicle_id);
        if (s_idx >= 0) {
            for (int i = 0; i < g_num_nodes; i++) {
                veh_node_t *n = &g_nodes[i];
                if (strcmp(n->vehicle_id, pi.vehicle_id) == 0) continue;
                int prev = n->last_seen_seq[s_idx];
                if (pi.seq <= prev) {
                    n->stale_dropped++;
                    if (g_rx_fp) {
                        fprintf(g_rx_fp, "{\"sim_ms\":%d,\"vehicle_id\":\"%s\",\"packet_id\":\"%s\",\"status\":\"STALE_DROPPED\"}\n",
                                sim_ms, n->vehicle_id, pkt_id);
                    }
                    continue;
                }
                if ((sim_ms - pi.issued_at_sim_ms) > pi.ttl_ms) {
                    n->expired_rx++;
                }
                n->last_seen_seq[s_idx] = pi.seq;
                n->peer_intents[s_idx] = pi;
            }
        }
        pthread_mutex_lock(&g_rx_lock);
    }
    pthread_mutex_unlock(&g_rx_lock);
}

static void step_decide(
    veh_node_t *n, int sim_ms, double speed, double d_to_cz, int approaching,
    const char *edge, const char *target_cz, int is_left_turn,
    const vis_peer_t *vis, int n_vis, int restore_ms,
    const char leaders[MAX_LEADERS][32], int n_leaders, int inject_unsafe,
    double *out_v, const char **out_act, const char **out_reason
) {
    if (inject_unsafe) {
        *out_v = 35.0; *out_act = "PROCEED"; *out_reason = "UNSAFE_CMD_INJECTED"; return;
    }
    if (!approaching || d_to_cz < 0.0 || strcmp(target_cz, "none") == 0) {
        if (n->partition_affected && n->degraded_before_restore && n->coop_recovered_ms < 0 && sim_ms >= restore_ms) {
            n->coop_recovered_ms = sim_ms - restore_ms;
        }
        *out_v = 13.89; *out_act = "PROCEED"; *out_reason = "PAST_STOP_LINE_CLEAR"; return;
    }

    int is_coop = (strcmp(g_mode, "cooperative") == 0);
    if (is_coop && n->partition_affected && n->intent_ready_ms < 0 && sim_ms >= restore_ms) {
        for (int i = 0; i < MAX_VEHS; i++) {
            peer_intent_t *p = &n->peer_intents[i];
            if (!p->valid) continue;
            if ((sim_ms - p->issued_at_sim_ms) <= p->ttl_ms && p->issued_at_sim_ms >= restore_ms) {
                n->intent_ready_ms = sim_ms - restore_ms;
                break;
            }
        }
    }

    double d_req = required_stopping_distance_m(speed);
    int ego_prio = is_priority_row(edge, is_left_turn);
    double eff_v = (speed > 4.0) ? speed : 4.0;
    int ego_entry = sim_ms + (int)((d_to_cz / eff_v) * 1000.0);
    int ego_exit = ego_entry + 2200;

    int local_block = 0;
    const char *local_reason = "";
    for (int i = 0; i < n_vis; i++) {
        const vis_peer_t *vp = &vis[i];
        if (strcmp(vp->cz, target_cz) != 0) continue;
        if (vp->in_cz) {
            local_block = 1;
            local_reason = "BLOCKED_BY_SILENT_OR_OCCUPIED";
            break;
        }
        if (movements_conflict_cz(target_cz, edge, is_left_turn, vp->cz, vp->edge, vp->is_left_turn)) {
            double vp_d = (vp->d_to_cz_m > 0.0) ? vp->d_to_cz_m : 0.0;
            double vp_v_raw = vp->speed_mps;
            if (vp_v_raw > 1.5 && vp_d <= required_stopping_distance_m(vp_v_raw) + 1.0) {
                local_block = 1;
                local_reason = "BLOCKED_BY_COMMITTED_PEER";
                break;
            }
            double vp_v = (vp_v_raw > 4.0) ? vp_v_raw : 4.0;
            int vp_entry = sim_ms + (int)((vp_d / vp_v) * 1000.0);
            if (!has_higher_row(n->vehicle_id, edge, is_left_turn, ego_entry, vp->vehicle_id, vp->edge, vp->is_left_turn, vp_entry)) {
                local_block = 1;
                local_reason = "LOCAL_VISIBLE_CONFLICT_YIELD";
                break;
            }
        }
    }

    if (local_block) {
        if (is_coop) {
            if (sim_ms <= restore_ms) n->degraded_before_restore = 1;
            if (sim_ms >= restore_ms) n->last_blocked_ms = sim_ms;
        }
        if (d_to_cz < d_req) {
            *out_v = 0.0; *out_act = "MITIGATION_MAX_DECEL"; *out_reason = local_reason; return;
        }
        double cv = max_safe_approach_speed_mps(d_to_cz);
        *out_v = cv; *out_act = (cv < 1.0) ? "STOP_YIELD" : "DECEL_YIELD"; *out_reason = local_reason; return;
    }

    if (strcmp(g_mode, "local_only") == 0) {
        if (d_to_cz > OCCLUSION_VIS_CLEAR_M) {
            double cv = max_safe_approach_speed_mps(d_to_cz - 4.0);
            if (cv < 4.5) cv = 4.5;
            if (cv > 13.89) cv = 13.89;
            *out_v = cv; *out_act = "APPROACH_CAUTION"; *out_reason = "LOCAL_ONLY_BLIND_ZONE_CAP"; return;
        }
        if (d_to_cz > 8.0) {
            *out_v = 4.5; *out_act = "APPROACH_CAUTION"; *out_reason = "LOCAL_ONLY_VIS_CREEP"; return;
        }
        *out_v = 11.5; *out_act = "PROCEED"; *out_reason = "LOCAL_ONLY_VIS_CONFIRMED"; return;
    }

    int expired_conflict = 0;
    int intent_yield = 0;
    int has_any_intent = 0;
    for (int i = 0; i < MAX_VEHS; i++) {
        peer_intent_t *p = &n->peer_intents[i];
        if (!p->valid) continue;
        has_any_intent = 1;
        int is_ldr = 0;
        for (int li = 0; li < n_leaders; li++) {
            if (strcmp(leaders[li], p->vehicle_id) == 0) { is_ldr = 1; break; }
        }
        if (!is_ldr) continue;
        if (!movements_conflict_cz(target_cz, edge, is_left_turn, p->cz, p->incoming_edge, p->is_left_turn)) continue;
        if ((sim_ms - p->issued_at_sim_ms) > p->ttl_ms) {
            expired_conflict = 1;
            continue;
        }
        if ((p->conflict_entry_sim_ms - sim_ms) > 5000) continue;
        if (time_windows_overlap(ego_entry, ego_exit, p->conflict_entry_sim_ms, p->conflict_exit_sim_ms)) {
            if (!has_higher_row(n->vehicle_id, edge, is_left_turn, ego_entry, p->vehicle_id, p->incoming_edge, p->is_left_turn, p->conflict_entry_sim_ms)) {
                intent_yield = 1;
            }
        }
    }

    int partition_blind = (!has_any_intent && !ego_prio);
    if (expired_conflict || partition_blind) {
        if (sim_ms <= restore_ms) n->degraded_before_restore = 1;
        if (sim_ms >= restore_ms) n->last_blocked_ms = sim_ms;
        double cv = max_safe_approach_speed_mps(d_to_cz);
        *out_v = cv; *out_act = (cv < 1.0) ? "STOP_YIELD" : "DECEL_YIELD"; *out_reason = "EXPIRED_OR_MISSING_INTENT_DEGRADED"; return;
    }
    if (intent_yield) {
        if (sim_ms >= restore_ms) n->last_blocked_ms = sim_ms;
        double cv = max_safe_approach_speed_mps(d_to_cz);
        *out_v = cv; *out_act = (cv < 1.0) ? "STOP_YIELD" : "DECEL_YIELD"; *out_reason = "COOP_INTENT_YIELD"; return;
    }
    if (!ego_prio && d_to_cz > OCCLUSION_VIS_CLEAR_M) {
        double cv = max_safe_approach_speed_mps(d_to_cz);
        if (cv < 6.5) cv = 6.5;
        *out_v = cv; *out_act = "APPROACH_CAUTION"; *out_reason = "WAIT_OCCLUSION_VIS_RECONFIRM"; return;
    }

    if (n->partition_affected && n->coop_recovered_ms < 0 && sim_ms >= restore_ms) {
        n->coop_recovered_ms = sim_ms - restore_ms;
    }
    *out_v = 11.5; *out_act = "PROCEED"; *out_reason = "COOP_CLEAR_PROCEED";
}

static int recv_exact(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, n - off, 0);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static void send_rpc_frame(int fd, const char *data, size_t len) {
    uint8_t hdr[4];
    hdr[0] = (uint8_t)((len >> 24) & 0xff);
    hdr[1] = (uint8_t)((len >> 16) & 0xff);
    hdr[2] = (uint8_t)((len >> 8) & 0xff);
    hdr[3] = (uint8_t)(len & 0xff);
    send_all(fd, hdr, 4);
    if (len > 0) send_all(fd, (const uint8_t *)data, len);
}

static char *read_file_all(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { *out_len = 0; return NULL; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); *out_len = 0; return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, fp);
    buf[rd] = '\0';
    fclose(fp);
    *out_len = rd;
    return buf;
}

static void load_specs_for_zone(const char *specs_path, const char *zone_filter) {
    size_t slen = 0;
    char *raw = read_file_all(specs_path, &slen);
    if (!raw) return;
    const char *p = raw;
    const char *end = raw + slen;
    g_num_nodes = 0;
    while (p < end && g_num_nodes < MAX_VEHS) {
        const char *ob = strchr(p, '{');
        if (!ob) break;
        const char *cb = find_matching_brace(ob, end);
        if (!cb) break;
        char zid[16] = "";
        json_get_str(ob, cb, "zone_id", zid, sizeof(zid));
        if (strcmp(zone_filter, "all") == 0 || strcmp(zid, zone_filter) == 0) {
            veh_node_t *n = &g_nodes[g_num_nodes++];
            memset(n, 0, sizeof(*n));
            json_get_str(ob, cb, "vehicle_id", n->vehicle_id, sizeof(n->vehicle_id));
            snprintf(n->zone_id, sizeof(n->zone_id), "%s", zid);
            json_get_bool(ob, cb, "silent", &n->silent);
            n->last_bcast_ms = -1000;
            n->intent_ready_ms = -1;
            n->coop_recovered_ms = -1;
            n->last_blocked_ms = -1;
        }
        p = cb + 1;
    }
    free(raw);
}

int main(int argc, char **argv) {
    int rx_port = 9101;
    int rpc_port = 8091;
    char gw_ip[64] = "10.0.2.2";
    int gw_port = 20001;
    char zone_id[16] = "zone-a";
    char specs_path[256] = "/data/pdx_qnx_fleet/specs.json";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host-id") == 0 && i + 1 < argc) snprintf(g_host_id, sizeof(g_host_id), "%s", argv[++i]);
        else if (strcmp(argv[i], "--zone-id") == 0 && i + 1 < argc) snprintf(zone_id, sizeof(zone_id), "%s", argv[++i]);
        else if (strcmp(argv[i], "--rx-port") == 0 && i + 1 < argc) rx_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--rpc-port") == 0 && i + 1 < argc) rpc_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--gw-ip") == 0 && i + 1 < argc) snprintf(gw_ip, sizeof(gw_ip), "%s", argv[++i]);
        else if (strcmp(argv[i], "--gw-port") == 0 && i + 1 < argc) gw_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--specs-json") == 0 && i + 1 < argc) snprintf(specs_path, sizeof(specs_path), "%s", argv[++i]);
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) snprintf(g_mode, sizeof(g_mode), "%s", argv[++i]);
    }

    load_specs_for_zone(specs_path, zone_id);
    snprintf(g_tx_log_path, sizeof(g_tx_log_path), "/tmp/tx_%s.jsonl", g_host_id);
    snprintf(g_rx_log_path, sizeof(g_rx_log_path), "/tmp/rx_%s.jsonl", g_host_id);
    g_tx_fp = fopen(g_tx_log_path, "w");
    g_rx_fp = fopen(g_rx_log_path, "w");

    g_rx_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval tv = {0, 200000};
    setsockopt(g_rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in rx_addr;
    memset(&rx_addr, 0, sizeof(rx_addr));
    rx_addr.sin_family = AF_INET;
    rx_addr.sin_addr.s_addr = INADDR_ANY;
    rx_addr.sin_port = htons((uint16_t)rx_port);
    if (bind(g_rx_sock, (struct sockaddr *)&rx_addr, sizeof(rx_addr)) != 0) {
        perror("bind rx");
        return 1;
    }

    g_tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&g_gw_addr, 0, sizeof(g_gw_addr));
    g_gw_addr.sin_family = AF_INET;
    g_gw_addr.sin_port = htons((uint16_t)gw_port);
    inet_pton(AF_INET, gw_ip, &g_gw_addr.sin_addr);

    int rpc_listen = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(rpc_listen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in rpc_addr;
    memset(&rpc_addr, 0, sizeof(rpc_addr));
    rpc_addr.sin_family = AF_INET;
    rpc_addr.sin_addr.s_addr = INADDR_ANY;
    rpc_addr.sin_port = htons((uint16_t)rpc_port);
    if (bind(rpc_listen, (struct sockaddr *)&rpc_addr, sizeof(rpc_addr)) != 0) {
        perror("bind rpc");
        return 1;
    }
    listen(rpc_listen, 4);

    pthread_t rx_tid;
    pthread_create(&rx_tid, NULL, rx_thread_fn, NULL);

    struct utsname u;
    uname(&u);
    printf("QNX_VEH_HOST_READY host=%s zone=%s nodes=%d os=%s release=%s rx=%d rpc=%d\n",
           g_host_id, zone_id, g_num_nodes, u.sysname, u.release, rx_port, rpc_port);
    fflush(stdout);

    static char *req_buf = NULL;
    static char *resp_buf = NULL;
    size_t req_cap = 4 * 1024 * 1024;
    size_t resp_cap = 2 * 1024 * 1024;
    req_buf = (char *)malloc(req_cap);
    resp_buf = (char *)malloc(resp_cap);

    while (!g_stop) {
        int cfd = accept(rpc_listen, NULL, NULL);
        if (cfd < 0) continue;
        int nd = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof(nd));
        while (!g_stop) {
            uint8_t hdr[4];
            if (recv_exact(cfd, hdr, 4) != 0) break;
            uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
            if (len >= req_cap) break;
            if (recv_exact(cfd, (uint8_t *)req_buf, len) != 0) break;
            req_buf[len] = '\0';
            const char *end = req_buf + len;

            if (len > 0 && req_buf[0] == 'B') {
                const uint8_t *p = (const uint8_t *)req_buf + 1;
                const uint8_t *bend = (const uint8_t *)req_buf + len;
                if (p + 20 + 32 > bend) break;
                int32_t sim_ms = 0, restore_ms = 7500, fault_enabled = 0, n_leaders = 0, n_vehs = 0;
                memcpy(&sim_ms, p, 4); p += 4;
                memcpy(&restore_ms, p, 4); p += 4;
                memcpy(&fault_enabled, p, 4); p += 4;
                memcpy(&n_leaders, p, 4); p += 4;
                memcpy(&n_vehs, p, 4); p += 4;
                char inject_vid[32];
                memcpy(inject_vid, p, 32); inject_vid[31] = '\0'; p += 32;

                static char leaders[MAX_LEADERS][32];
                if (n_leaders > MAX_LEADERS) n_leaders = MAX_LEADERS;
                for (int i = 0; i < n_leaders && p + 32 <= bend; i++) {
                    memcpy(leaders[i], p, 32);
                    leaders[i][31] = '\0';
                    p += 32;
                }

                int64_t t_c0 = mono_us();
                drain_rx(sim_ms);

                uint8_t *rp = (uint8_t *)resp_buf;
                rp[0] = 'R';
                memset(rp + 1, 0, 16 + 16 + 4 + 4 + 8);
                strncpy((char *)(rp + 1), u.sysname, 15);
                strncpy((char *)(rp + 17), u.release, 15);
                int32_t rpid = (int32_t)getpid();
                memcpy(rp + 33, &rpid, 4);
                int32_t rcmds = n_vehs;
                memcpy(rp + 37, &rcmds, 4);
                size_t roff = 49;

                for (int vi = 0; vi < n_vehs; vi++) {
                    if (p + 72 + 16 + 16 > bend) break;
                    char vid[32], edge[32], tcz[8];
                    memcpy(vid, p, 32); vid[31] = '\0'; p += 32;
                    memcpy(edge, p, 32); edge[31] = '\0'; p += 32;
                    memcpy(tcz, p, 8); tcz[7] = '\0'; p += 8;
                    int32_t is_left = 0, in_cz = 0, approaching = 0, n_vis_in = 0;
                    memcpy(&is_left, p, 4); p += 4;
                    memcpy(&in_cz, p, 4); p += 4;
                    memcpy(&approaching, p, 4); p += 4;
                    memcpy(&n_vis_in, p, 4); p += 4;
                    double spd = 0.0, d_cz = -1.0;
                    memcpy(&spd, p, 8); p += 8;
                    memcpy(&d_cz, p, 8); p += 8;

                    vis_peer_t vis[MAX_VIS];
                    int n_vis = 0;
                    for (int vj = 0; vj < n_vis_in && p + 72 + 8 + 16 <= bend; vj++) {
                        if (n_vis < MAX_VIS) {
                            vis_peer_t *vp = &vis[n_vis++];
                            memcpy(vp->vehicle_id, p, 32); vp->vehicle_id[31] = '\0';
                            memcpy(vp->edge, p + 32, 32); vp->edge[31] = '\0';
                            memcpy(vp->cz, p + 64, 8); vp->cz[7] = '\0';
                            memcpy(&vp->is_left_turn, p + 72, 4);
                            memcpy(&vp->in_cz, p + 76, 4);
                            memcpy(&vp->speed_mps, p + 80, 8);
                            memcpy(&vp->d_to_cz_m, p + 88, 8);
                        }
                        p += 96;
                    }

                    double cmd_v = 11.5;
                    veh_node_t *node = find_node(vid);
                    if (node) {
                        if (fault_enabled && sim_ms >= 5500 && sim_ms < 7500) node->partition_affected = 1;
                        if (sim_ms >= restore_ms && approaching) node->still_approaching_at_restore = 1;
                        if (!node->silent && strcmp(g_mode, "local_only") != 0 && approaching &&
                            strcmp(tcz, "none") != 0 && (sim_ms - node->last_bcast_ms) >= BROADCAST_PERIOD_MS) {
                            node->last_bcast_ms = sim_ms;
                            node->seq++;
                            double ev = (spd > 4.0) ? spd : 4.0;
                            int entry_ms = sim_ms + (int)(((d_cz > 0.0 ? d_cz : 0.0) / ev) * 1000.0);
                            node->tx_count++;
                            char pkt_json[512];
                            int plen = snprintf(pkt_json, sizeof(pkt_json),
                                "{\"schema\":\"pdx.driving_intent.v2\",\"vehicle_id\":\"%s\",\"zone_id\":\"%s\","
                                "\"seq\":%d,\"issued_at_sim_ms\":%d,\"ttl_ms\":%d,\"incoming_edge\":\"%s\","
                                "\"is_left_turn\":%s,\"conflict_zone_id\":\"%s_cz\",\"conflict_entry_sim_ms\":%d,"
                                "\"conflict_exit_sim_ms\":%d,\"speed_mps\":%.3f,\"intended_action\":\"PROCEED\","
                                "\"packet_id\":\"%s:%d\"}",
                                node->vehicle_id, node->zone_id, node->seq, sim_ms, TTL_MS_DEFAULT, edge,
                                is_left ? "true" : "false", tcz, entry_ms, entry_ms + 2200, spd,
                                node->vehicle_id, node->seq);
                            sendto(g_tx_sock, pkt_json, (size_t)plen, 0, (struct sockaddr *)&g_gw_addr, sizeof(g_gw_addr));
                            if (g_tx_fp) {
                                fprintf(g_tx_fp, "{\"sim_ms\":%d,\"vehicle_id\":\"%s\",\"packet_id\":\"%s:%d\"}\n",
                                        sim_ms, node->vehicle_id, node->vehicle_id, node->seq);
                            }
                        }
                        const char *act = "PROCEED", *rsn = "OK";
                        step_decide(node, sim_ms, spd, d_cz, approaching, edge, tcz, is_left,
                                    vis, n_vis, restore_ms, leaders, n_leaders,
                                    (inject_vid[0] && strcmp(vid, inject_vid) == 0),
                                    &cmd_v, &act, &rsn);
                    }
                    memcpy(rp + roff, &cmd_v, 8);
                    roff += 8;
                }
                int64_t comp_us = mono_us() - t_c0;
                memcpy(rp + 41, &comp_us, 8);
                send_rpc_frame(cfd, (const char *)rp, roff);
                continue;
            }

            char op[32] = "";
            json_get_str(req_buf, end, "op", op, sizeof(op));

            if (strcmp(op, "STEP_BATCH") == 0) {
                int sim_ms = 0, restore_ms = 7500, fault_enabled = 0;
                char inject_vid[32] = "";
                json_get_int(req_buf, end, "sim_ms", &sim_ms);
                json_get_int(req_buf, end, "restore_ms", &restore_ms);
                json_get_bool(req_buf, end, "fault_enabled", &fault_enabled);
                json_get_str(req_buf, end, "inject_unsafe_vid", inject_vid, sizeof(inject_vid));

                /* Parse leader_ids array */
                static char leaders[MAX_LEADERS][32];
                int n_leaders = 0;
                const char *lp = strstr(req_buf, "\"leader_ids\"");
                if (lp && lp < end) {
                    const char *lb = strchr(lp, '[');
                    const char *le = lb ? find_matching_brace(lb, end) : NULL;
                    if (lb && le) {
                        const char *q = lb + 1;
                        while (q < le && n_leaders < MAX_LEADERS) {
                            const char *s1 = strchr(q, '"');
                            if (!s1 || s1 >= le) break;
                            const char *s2 = strchr(s1 + 1, '"');
                            if (!s2 || s2 >= le) break;
                            size_t ll = (size_t)(s2 - (s1 + 1));
                            if (ll > 31) ll = 31;
                            memcpy(leaders[n_leaders], s1 + 1, ll);
                            leaders[n_leaders][ll] = '\0';
                            n_leaders++;
                            q = s2 + 1;
                        }
                    }
                }

                drain_rx(sim_ms);

                size_t roff = 0;
                roff += (size_t)snprintf(resp_buf + roff, resp_cap - roff,
                                         "{\"ok\":true,\"os\":\"%s\",\"release\":\"%s\",\"pid\":%d,\"cmds\":{",
                                         u.sysname, u.release, (int)getpid());
                int first_cmd = 1;

                const char *vp_arr = strstr(req_buf, "\"vehicles\"");
                const char *ab = vp_arr ? strchr(vp_arr, '[') : NULL;
                const char *ae = ab ? find_matching_brace(ab, end) : NULL;
                if (ab && ae) {
                    const char *cur = ab + 1;
                    while (cur < ae) {
                        const char *ob = strchr(cur, '{');
                        if (!ob || ob >= ae) break;
                        const char *cb = find_matching_brace(ob, ae);
                        if (!cb) break;

                        char vid[32] = "", edge[32] = "", tcz[8] = "none";
                        int is_left = 0, in_cz = 0, approaching = 0;
                        double spd = 0.0, d_cz = -1.0;
                        json_get_str(ob, cb, "vehicle_id", vid, sizeof(vid));
                        json_get_str(ob, cb, "edge", edge, sizeof(edge));
                        json_get_str(ob, cb, "target_cz", tcz, sizeof(tcz));
                        json_get_bool(ob, cb, "is_left_turn", &is_left);
                        json_get_double(ob, cb, "speed_mps", &spd);
                        json_get_double(ob, cb, "d_to_cz_m", &d_cz);
                        json_get_bool(ob, cb, "in_cz", &in_cz);
                        json_get_bool(ob, cb, "approaching", &approaching);

                        /* Parse visible_peers inside this vehicle object */
                        vis_peer_t vis[MAX_VIS];
                        int n_vis = 0;
                        const char *vpp = strstr(ob, "\"visible_peers\"");
                        if (vpp && vpp < cb) {
                            const char *vb = strchr(vpp, '[');
                            const char *ve = vb ? find_matching_brace(vb, cb) : NULL;
                            if (vb && ve) {
                                const char *vc = vb + 1;
                                while (vc < ve && n_vis < MAX_VIS) {
                                    const char *vob = strchr(vc, '{');
                                    if (!vob || vob >= ve) break;
                                    const char *vcb = find_matching_brace(vob, ve);
                                    if (!vcb) break;
                                    vis_peer_t *vp = &vis[n_vis++];
                                    memset(vp, 0, sizeof(*vp));
                                    json_get_str(vob, vcb, "vehicle_id", vp->vehicle_id, sizeof(vp->vehicle_id));
                                    json_get_str(vob, vcb, "edge", vp->edge, sizeof(vp->edge));
                                    json_get_str(vob, vcb, "target_cz", vp->cz, sizeof(vp->cz));
                                    json_get_bool(vob, vcb, "is_left_turn", &vp->is_left_turn);
                                    json_get_double(vob, vcb, "speed_mps", &vp->speed_mps);
                                    json_get_double(vob, vcb, "d_to_cz_m", &vp->d_to_cz_m);
                                    json_get_bool(vob, vcb, "in_cz", &vp->in_cz);
                                    vc = vcb + 1;
                                }
                            }
                        }

                        veh_node_t *node = find_node(vid);
                        if (node) {
                            if (fault_enabled && sim_ms >= 5500 && sim_ms < 7500) node->partition_affected = 1;
                            if (sim_ms >= restore_ms && approaching) node->still_approaching_at_restore = 1;

                            if (!node->silent && strcmp(g_mode, "local_only") != 0 && approaching &&
                                strcmp(tcz, "none") != 0 && (sim_ms - node->last_bcast_ms) >= BROADCAST_PERIOD_MS) {
                                node->last_bcast_ms = sim_ms;
                                node->seq++;
                                double ev = (spd > 4.0) ? spd : 4.0;
                                int entry_ms = sim_ms + (int)(((d_cz > 0.0 ? d_cz : 0.0) / ev) * 1000.0);
                                node->tx_count++;
                                char pkt_json[512];
                                int plen = snprintf(pkt_json, sizeof(pkt_json),
                                    "{\"schema\":\"pdx.driving_intent.v2\",\"vehicle_id\":\"%s\",\"zone_id\":\"%s\","
                                    "\"seq\":%d,\"issued_at_sim_ms\":%d,\"ttl_ms\":%d,\"incoming_edge\":\"%s\","
                                    "\"is_left_turn\":%s,\"conflict_zone_id\":\"%s_cz\",\"conflict_entry_sim_ms\":%d,"
                                    "\"conflict_exit_sim_ms\":%d,\"speed_mps\":%.3f,\"intended_action\":\"PROCEED\","
                                    "\"packet_id\":\"%s:%d\"}",
                                    node->vehicle_id, node->zone_id, node->seq, sim_ms, TTL_MS_DEFAULT, edge,
                                    is_left ? "true" : "false", tcz, entry_ms, entry_ms + 2200, spd,
                                    node->vehicle_id, node->seq);
                                sendto(g_tx_sock, pkt_json, (size_t)plen, 0, (struct sockaddr *)&g_gw_addr, sizeof(g_gw_addr));
                                if (g_tx_fp) {
                                    fprintf(g_tx_fp, "{\"sim_ms\":%d,\"vehicle_id\":\"%s\",\"packet_id\":\"%s:%d\"}\n",
                                            sim_ms, node->vehicle_id, node->vehicle_id, node->seq);
                                }
                            }

                            double cmd_v = 11.5;
                            const char *act = "PROCEED", *rsn = "OK";
                            step_decide(node, sim_ms, spd, d_cz, approaching, edge, tcz, is_left,
                                        vis, n_vis, restore_ms, leaders, n_leaders,
                                        (inject_vid[0] && strcmp(vid, inject_vid) == 0),
                                        &cmd_v, &act, &rsn);
                            roff += (size_t)snprintf(resp_buf + roff, resp_cap - roff,
                                                     "%s\"%s\":{\"cmd_v\":%.3f,\"action\":\"%s\",\"reason\":\"%s\"}",
                                                     first_cmd ? "" : ",", vid, cmd_v, act, rsn);
                            first_cmd = 0;
                        }
                        cur = cb + 1;
                    }
                }
                roff += (size_t)snprintf(resp_buf + roff, resp_cap - roff, "}}");
                send_rpc_frame(cfd, resp_buf, roff);
            } else if (strcmp(op, "GET_SUMMARY") == 0) {
                if (g_tx_fp) fflush(g_tx_fp);
                if (g_rx_fp) fflush(g_rx_fp);
                size_t roff = 0;
                roff += (size_t)snprintf(resp_buf + roff, resp_cap - roff,
                    "{\"host_id\":\"%s\",\"os\":\"%s\",\"release\":\"%s\",\"machine\":\"%s\","
                    "\"pid\":%d,\"rx_queue_depth_max\":%d,\"cpu_time_s\":0.0,\"nodes\":{",
                    g_host_id, u.sysname, u.release, u.machine, (int)getpid(), g_rx_q_max);
                for (int i = 0; i < g_num_nodes; i++) {
                    veh_node_t *n = &g_nodes[i];
                    char ir_buf[16], cr_buf[16], lb_buf[16];
                    if (n->intent_ready_ms >= 0) snprintf(ir_buf, sizeof(ir_buf), "%d", n->intent_ready_ms); else strcpy(ir_buf, "null");
                    if (n->coop_recovered_ms >= 0) snprintf(cr_buf, sizeof(cr_buf), "%d", n->coop_recovered_ms); else strcpy(cr_buf, "null");
                    if (n->last_blocked_ms >= 0) snprintf(lb_buf, sizeof(lb_buf), "%d", n->last_blocked_ms); else strcpy(lb_buf, "null");
                    roff += (size_t)snprintf(resp_buf + roff, resp_cap - roff,
                        "%s\"%s\":{\"silent\":%s,\"partition_affected\":%s,\"degraded_before_restore\":%s,"
                        "\"still_approaching_at_restore\":%s,\"intent_ready_ms\":%s,\"coop_recovered_ms\":%s,"
                        "\"last_blocked_ms\":%s,\"stale_dropped\":%d,\"stale_overwrites\":%d,\"expired_rx\":%d,\"tx_count\":%d}",
                        (i == 0) ? "" : ",", n->vehicle_id,
                        n->silent ? "true" : "false",
                        n->partition_affected ? "true" : "false",
                        n->degraded_before_restore ? "true" : "false",
                        n->still_approaching_at_restore ? "true" : "false",
                        ir_buf, cr_buf, lb_buf,
                        n->stale_dropped, n->stale_overwrites, n->expired_rx, n->tx_count);
                }
                roff += (size_t)snprintf(resp_buf + roff, resp_cap - roff, "}}");
                send_rpc_frame(cfd, resp_buf, roff);
            } else if (strcmp(op, "GET_LOG") == 0) {
                char kind[16] = "tx";
                json_get_str(req_buf, end, "kind", kind, sizeof(kind));
                if (g_tx_fp) fflush(g_tx_fp);
                if (g_rx_fp) fflush(g_rx_fp);
                size_t flen = 0;
                char *fdata = read_file_all(strcmp(kind, "rx") == 0 ? g_rx_log_path : g_tx_log_path, &flen);
                send_rpc_frame(cfd, fdata ? fdata : "", flen);
                if (fdata) free(fdata);
            } else if (strcmp(op, "SHUTDOWN") == 0) {
                send_rpc_frame(cfd, "{\"ok\":true}", 11);
                g_stop = 1;
                break;
            }
        }
        close(cfd);
    }

    pthread_join(rx_tid, NULL);
    close(rpc_listen);
    close(g_rx_sock);
    close(g_tx_sock);
    if (g_tx_fp) fclose(g_tx_fp);
    if (g_rx_fp) fclose(g_rx_fp);
    free(req_buf);
    free(resp_buf);
    return 0;
}
