/**
 * @file gate_submit.c
 * @brief CLI Client submitting signed manifest + firmware or querying status on /dev/pdxguardian
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint8_t *read_entire_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    *out_len = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    return buf;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--status") == 0) {
        int fd = open("/dev/pdxguardian", O_RDWR);
        if (fd < 0) {
            perror("open(/dev/pdxguardian)");
            return 1;
        }
        char status_json[2048];
        ssize_t rlen = read(fd, status_json, sizeof(status_json) - 1);
        if (rlen > 0) {
            status_json[rlen] = '\0';
            printf("%s", status_json);
        }
        close(fd);
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <manifest_164b.bin> <firmware.bin> | --status\n", argv[0]);
        return 1;
    }

    size_t m_len = 0, fw_len = 0;
    uint8_t *m_buf = read_entire_file(argv[1], &m_len);
    uint8_t *fw_buf = read_entire_file(argv[2], &fw_len);
    if (!m_buf || !fw_buf) {
        fprintf(stderr, "Failed to read input files.\n");
        free(m_buf);
        free(fw_buf);
        return 1;
    }

    int fd = open("/dev/pdxguardian", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/pdxguardian)");
        free(m_buf);
        free(fw_buf);
        return 1;
    }

    if (write(fd, m_buf, m_len) != (ssize_t)m_len) {
        perror("write(manifest)");
        close(fd);
        free(m_buf);
        free(fw_buf);
        return 1;
    }

    size_t sent = 0;
    while (sent < fw_len) {
        size_t chunk = (fw_len - sent > 32768) ? 32768 : (fw_len - sent);
        ssize_t n = write(fd, fw_buf + sent, chunk);
        if (n <= 0) {
            perror("write(firmware)");
            close(fd);
            free(m_buf);
            free(fw_buf);
            return 1;
        }
        sent += (size_t)n;
    }

    char receipt[2048];
    ssize_t rlen = read(fd, receipt, sizeof(receipt) - 1);
    if (rlen > 0) {
        receipt[rlen] = '\0';
        printf("%s", receipt);
    } else {
        fprintf(stderr, "{\"operation_id\":\"unknown\",\"decision\":\"UNKNOWN_OUTCOME\",\"reason\":\"no_reply_from_gate\"}\n");
    }

    close(fd);
    free(m_buf);
    free(fw_buf);
    return 0;
}
