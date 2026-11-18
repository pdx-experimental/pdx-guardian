#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/neutrino.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int enabled;
    int cpu_id;
    int requested_policy;
    int requested_priority;
    int actual_policy;
    int actual_priority;
    int affinity_ok;
    int sched_ok;
    const char *work_dir;
    int no_fsync;
    volatile int *stop_flag;
    uint64_t sha256_iterations;
    uint64_t io_write_ok;
    uint64_t io_fsync_ok;
    uint64_t io_errors;
} worker_args_t;

static int pin_thread_to_cpu(int cpu_id) {
    unsigned runmask = 1u << (unsigned)cpu_id;
    if (ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)runmask) == -1) {
        return -1;
    }
    return 0;
}

static int set_and_verify_thread_rt_prio(int policy, int priority, int *out_policy, int *out_prio) {
    struct sched_param param;
    memset(&param, 0, sizeof(param));
    param.sched_priority = priority;
    if (pthread_setschedparam(pthread_self(), policy, &param) != 0) {
        return -1;
    }
    struct sched_param actual;
    int apol = 0;
    if (pthread_getschedparam(pthread_self(), &apol, &actual) != 0) {
        return -1;
    }
    if (out_policy) *out_policy = apol;
    if (out_prio) *out_prio = actual.sched_priority;
    if (apol != policy || actual.sched_priority != priority) {
        return -1;
    }
    return 0;
}

static const char *policy_name(int policy) {
    if (policy == SCHED_FIFO) return "SCHED_FIFO";
    if (policy == SCHED_RR) return "SCHED_RR";
    if (policy == SCHED_OTHER) return "SCHED_OTHER";
    return "UNKNOWN";
}

static void *update_worker_thread(void *arg) {
    worker_args_t *w = (worker_args_t *)arg;
    w->affinity_ok = (pin_thread_to_cpu(w->cpu_id) == 0) ? 1 : 0;
    w->sched_ok = (set_and_verify_thread_rt_prio(
                       w->requested_policy, w->requested_priority,
                       &w->actual_policy, &w->actual_priority) == 0)
                      ? 1
                      : 0;

    int fd = -1;
    if (!w->no_fsync) {
        char io_path[512];
        snprintf(io_path, sizeof(io_path), "%s/jitter_worker_io.bin", w->work_dir);
        fd = open(io_path, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (fd < 0) {
            w->io_errors++;
        }
    }

    uint8_t buf[65536];
    for (size_t i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)(i & 0xFF);
    }
    uint8_t digest[32];
    unsigned int dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    uint64_t iter = 0;
    while (!(*w->stop_flag)) {
        if (ctx && md) {
            if (EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
                EVP_DigestUpdate(ctx, buf, sizeof(buf)) == 1 &&
                EVP_DigestFinal_ex(ctx, digest, &dlen) == 1) {
                buf[0] ^= digest[0];
                w->sha256_iterations++;
            } else {
                w->io_errors++;
            }
        }
        if (fd >= 0 && (iter % 4 == 0)) {
            if ((iter % 256) == 0) {
                if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
                    w->io_errors++;
                }
            }
            ssize_t wr = write(fd, buf, 4096);
            if (wr == 4096) {
                w->io_write_ok++;
            } else {
                w->io_errors++;
            }
            if ((iter % 16) == 0) {
                if (fsync(fd) == 0) {
                    w->io_fsync_ok++;
                } else {
                    w->io_errors++;
                }
            }
        }
        iter++;
    }

    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static void timespec_add_ns(struct timespec *ts, int64_t ns) {
    ts->tv_nsec += ns;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_nsec -= 1000000000L;
        ts->tv_sec += 1;
    }
}

int main(int argc, char **argv) {
    const char *scenario = "same-vcpu";
    int round_idx = 1;
    int warmup = 1000;
    int samples = 10000;
    int period_us = 10000;
    const char *work_dir = "/data/var/tmp/jitter_work";
    const char *out_json = "/data/var/tmp/jitter_result.json";
    const char *samples_csv = NULL;
    int no_fsync = 0;
    long clock_period_ns = 0;
    long phase_offset_us = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            scenario = argv[++i];
        } else if (strcmp(argv[i], "--round") == 0 && i + 1 < argc) {
            round_idx = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            warmup = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
            samples = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--period-us") == 0 && i + 1 < argc) {
            period_us = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--work-dir") == 0 && i + 1 < argc) {
            work_dir = argv[++i];
        } else if (strcmp(argv[i], "--out-json") == 0 && i + 1 < argc) {
            out_json = argv[++i];
        } else if (strcmp(argv[i], "--samples-csv") == 0 && i + 1 < argc) {
            samples_csv = argv[++i];
        } else if (strcmp(argv[i], "--no-fsync") == 0) {
            no_fsync = 1;
        } else if (strcmp(argv[i], "--clock-period-ns") == 0 && i + 1 < argc) {
            clock_period_ns = atol(argv[++i]);
        } else if (strcmp(argv[i], "--phase-offset-us") == 0 && i + 1 < argc) {
            phase_offset_us = atol(argv[++i]);
        }
    }

    int worker_enabled = (strcmp(scenario, "idle") != 0) ? 1 : 0;
    if (strcmp(scenario, "idle") != 0 &&
        strcmp(scenario, "same-vcpu") != 0 &&
        strcmp(scenario, "separated-vcpu") != 0) {
        fprintf(stderr, "Invalid scenario: %s\n", scenario);
        return 1;
    }
    if (samples <= 0 || warmup < 0 || period_us <= 0) {
        fprintf(stderr, "Invalid parameters\n");
        return 1;
    }

    mkdir(work_dir, 0755);

    struct _clockperiod old_cp = {0, 0};
    struct _clockperiod cur_cp = {0, 0};
    int clock_period_changed = 0;
    if (clock_period_ns > 0) {
        struct _clockperiod new_cp = {(unsigned long)clock_period_ns, 0};
        if (ClockPeriod(CLOCK_REALTIME, &new_cp, &old_cp, 0) == 0) {
            clock_period_changed = 1;
        }
    }
    ClockPeriod(CLOCK_REALTIME, NULL, &cur_cp, 0);
    unsigned long actual_clock_period_ns = cur_cp.nsec;
    int clock_period_ok = (clock_period_ns <= 0) || clock_period_changed;

    int ecu_cpu = 0;
    int worker_cpu = (strcmp(scenario, "separated-vcpu") == 0) ? 1 : 0;

    int ecu_affinity_ok = (pin_thread_to_cpu(ecu_cpu) == 0) ? 1 : 0;
    int ecu_actual_policy = 0;
    int ecu_actual_prio = 0;
    int ecu_sched_ok = (set_and_verify_thread_rt_prio(
                            SCHED_FIFO, 50, &ecu_actual_policy, &ecu_actual_prio) == 0)
                           ? 1
                           : 0;

    volatile int stop_flag = 0;
    worker_args_t wargs;
    memset(&wargs, 0, sizeof(wargs));
    wargs.enabled = worker_enabled;
    wargs.cpu_id = worker_cpu;
    wargs.requested_policy = SCHED_RR;
    wargs.requested_priority = 10;
    wargs.work_dir = work_dir;
    wargs.no_fsync = no_fsync;
    wargs.stop_flag = &stop_flag;

    pthread_t worker_tid;
    int worker_started = 0;
    if (worker_enabled) {
        if (pthread_create(&worker_tid, NULL, update_worker_thread, &wargs) != 0) {
            fprintf(stderr, "Failed to create update_worker thread\n");
            return 1;
        }
        worker_started = 1;
    } else {
        wargs.affinity_ok = 1;
        wargs.sched_ok = 1;
    }

    double *signed_lat_us = calloc((size_t)samples, sizeof(double));
    double *abs_lat_us = calloc((size_t)samples, sizeof(double));
    double *work_span_us_arr = calloc((size_t)samples, sizeof(double));
    if (!signed_lat_us || !abs_lat_us || !work_span_us_arr) {
        fprintf(stderr, "OOM allocating sample buffers\n");
        stop_flag = 1;
        if (worker_started) pthread_join(worker_tid, NULL);
        free(signed_lat_us);
        free(abs_lat_us);
        free(work_span_us_arr);
        return 1;
    }

    const int64_t period_ns = (int64_t)period_us * 1000LL;
    struct timespec next_wakeup;
    clock_gettime(CLOCK_MONOTONIC, &next_wakeup);
    if (phase_offset_us > 0) {
        timespec_add_ns(&next_wakeup, (int64_t)phase_offset_us * 1000LL);
    }

    int total = warmup + samples;
    int completed_samples = 0;
    int wakeup_overruns = 0;
    int ecu_deadline_misses = 0;
    int sleep_error = 0;
    double sum_abs_us = 0.0;
    double min_signed_us = 1e12;
    double max_signed_us = -1e12;
    double max_abs_us = 0.0;

    for (int i = 0; i < total; i++) {
        timespec_add_ns(&next_wakeup, period_ns);
        int rc;
        do {
            rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_wakeup, NULL);
        } while (rc == EINTR);

        if (rc != 0) {
            fprintf(stderr, "clock_nanosleep error at iter=%d: %s\n", i, strerror(rc));
            sleep_error = 1;
            break;
        }

        struct timespec actual;
        clock_gettime(CLOCK_MONOTONIC, &actual);

        /* Simulated deterministic ECU control step (lightweight state check) */
        volatile uint64_t ecu_acc = (uint64_t)i * 2654435761ULL;
        ecu_acc ^= (ecu_acc >> 16);
        struct timespec work_end;
        clock_gettime(CLOCK_MONOTONIC, &work_end);

        int64_t diff_ns = ((int64_t)actual.tv_sec - (int64_t)next_wakeup.tv_sec) * 1000000000LL +
                          ((int64_t)actual.tv_nsec - (int64_t)next_wakeup.tv_nsec);
        int64_t work_span_ns = ((int64_t)work_end.tv_sec - (int64_t)next_wakeup.tv_sec) * 1000000000LL +
                               ((int64_t)work_end.tv_nsec - (int64_t)next_wakeup.tv_nsec);

        if (i >= warmup) {
            int idx = completed_samples;
            if (diff_ns > period_ns) {
                wakeup_overruns++;
            }
            if (work_span_ns > period_ns) {
                ecu_deadline_misses++;
            }
            double s_us = (double)diff_ns / 1000.0;
            double a_us = fabs(s_us);
            double w_us = (double)work_span_ns / 1000.0;
            signed_lat_us[idx] = s_us;
            abs_lat_us[idx] = a_us;
            work_span_us_arr[idx] = w_us;
            sum_abs_us += a_us;
            if (s_us < min_signed_us) min_signed_us = s_us;
            if (s_us > max_signed_us) max_signed_us = s_us;
            if (a_us > max_abs_us) max_abs_us = a_us;
            completed_samples++;
        }
    }

    stop_flag = 1;
    if (worker_started) {
        pthread_join(worker_tid, NULL);
    }

    if (samples_csv && completed_samples > 0) {
        FILE *cfp = fopen(samples_csv, "w");
        if (cfp) {
            fprintf(cfp, "sample_idx,signed_wakeup_us,work_span_us\n");
            for (int i = 0; i < completed_samples; i++) {
                fprintf(cfp, "%d,%.3f,%.3f\n", i, signed_lat_us[i], work_span_us_arr[i]);
            }
            fclose(cfp);
        }
    }

    double p50_us = 0.0, p95_us = 0.0, p99_us = 0.0, p999_us = 0.0, mean_abs_us = 0.0;
    if (completed_samples > 0) {
        qsort(abs_lat_us, (size_t)completed_samples, sizeof(double), cmp_double);
        p50_us = abs_lat_us[(size_t)((completed_samples - 1) * 0.50)];
        p95_us = abs_lat_us[(size_t)((completed_samples - 1) * 0.95)];
        p99_us = abs_lat_us[(size_t)((completed_samples - 1) * 0.99)];
        p999_us = abs_lat_us[(size_t)((completed_samples - 1) * 0.999)];
        mean_abs_us = sum_abs_us / (double)completed_samples;
    } else {
        min_signed_us = 0.0;
        max_signed_us = 0.0;
    }

    int worker_io_ok = (!worker_enabled) || (no_fsync ? (wargs.io_errors == 0 && wargs.sha256_iterations > 0) : (wargs.io_errors == 0 && wargs.io_write_ok > 0 && wargs.io_fsync_ok > 0));
    int config_valid = (ecu_affinity_ok && ecu_sched_ok &&
                        wargs.affinity_ok && wargs.sched_ok &&
                        worker_io_ok && clock_period_ok && !sleep_error &&
                        completed_samples == samples)
                           ? 1
                           : 0;
    int thresholds_passed = (config_valid &&
                             wakeup_overruns == 0 &&
                             ecu_deadline_misses == 0 &&
                             p50_us <= 50.0 &&
                             p99_us <= 250.0 &&
                             max_abs_us <= 1500.0)
                                ? 1
                                : 0;

    char json_buf[3072];
    snprintf(json_buf, sizeof(json_buf),
             "{\n"
             "  \"scenario\": \"%s\",\n"
             "  \"round\": %d,\n"
             "  \"worker_enabled\": %s,\n"
             "  \"ecu_cpu\": %d,\n"
             "  \"worker_cpu\": %d,\n"
             "  \"ecu_affinity_ok\": %s,\n"
             "  \"ecu_sched_ok\": %s,\n"
             "  \"ecu_actual_policy\": \"%s\",\n"
             "  \"ecu_actual_priority\": %d,\n"
             "  \"worker_affinity_ok\": %s,\n"
             "  \"worker_sched_ok\": %s,\n"
             "  \"worker_actual_policy\": \"%s\",\n"
             "  \"worker_actual_priority\": %d,\n"
             "  \"config_valid\": %s,\n"
             "  \"warmup_cycles\": %d,\n"
             "  \"requested_samples\": %d,\n"
             "  \"completed_samples\": %d,\n"
             "  \"period_us\": %d,\n"
             "  \"requested_clock_period_ns\": %ld,\n"
             "  \"actual_clock_period_ns\": %lu,\n"
             "  \"phase_offset_us\": %ld,\n"
             "  \"no_fsync\": %s,\n"
             "  \"wakeup_overruns\": %d,\n"
             "  \"ecu_deadline_misses\": %d,\n"
             "  \"min_signed_us\": %.3f,\n"
             "  \"max_signed_us\": %.3f,\n"
             "  \"mean_abs_us\": %.3f,\n"
             "  \"p50_us\": %.3f,\n"
             "  \"p95_us\": %.3f,\n"
             "  \"p99_us\": %.3f,\n"
             "  \"p999_us\": %.3f,\n"
             "  \"max_abs_us\": %.3f,\n"
             "  \"worker_sha256_iterations\": %llu,\n"
             "  \"worker_io_write_ok\": %llu,\n"
             "  \"worker_io_fsync_ok\": %llu,\n"
             "  \"worker_io_errors\": %llu,\n"
             "  \"thresholds_passed\": %s\n"
             "}\n",
             scenario, round_idx,
             worker_enabled ? "true" : "false",
             ecu_cpu, worker_enabled ? worker_cpu : -1,
             ecu_affinity_ok ? "true" : "false",
             ecu_sched_ok ? "true" : "false",
             policy_name(ecu_actual_policy), ecu_actual_prio,
             wargs.affinity_ok ? "true" : "false",
             wargs.sched_ok ? "true" : "false",
             worker_enabled ? policy_name(wargs.actual_policy) : "NONE",
             worker_enabled ? wargs.actual_priority : 0,
             config_valid ? "true" : "false",
             warmup, samples, completed_samples, period_us,
             clock_period_ns, actual_clock_period_ns,
             phase_offset_us,
             no_fsync ? "true" : "false",
             wakeup_overruns, ecu_deadline_misses,
             min_signed_us, max_signed_us, mean_abs_us,
             p50_us, p95_us, p99_us, p999_us, max_abs_us,
             (unsigned long long)wargs.sha256_iterations,
             (unsigned long long)wargs.io_write_ok,
             (unsigned long long)wargs.io_fsync_ok,
             (unsigned long long)wargs.io_errors,
             thresholds_passed ? "true" : "false");

    FILE *fp = fopen(out_json, "w");
    if (fp) {
        fputs(json_buf, fp);
        fclose(fp);
    }
    printf("JITTER_RESULT_BEGIN\n%sJITTER_RESULT_END\n", json_buf);

    if (clock_period_changed) {
        ClockPeriod(CLOCK_REALTIME, &old_cp, NULL, 0);
    }
    free(signed_lat_us);
    free(abs_lat_us);
    free(work_span_us_arr);
    return config_valid ? 0 : 2;
}
