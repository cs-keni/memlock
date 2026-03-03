/* HARD: Enterprise-style safe code - config from env, proper error handling.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 256
#define MAX_CHUNK  (1024 * 1024)

/* Config from environment - no hardcoded secrets */
typedef struct {
    char db_host[64];
    size_t chunk_size;
} Config;

static int load_config(Config *cfg) {
    const char *host = getenv("DB_HOST");
    if (host != NULL) {
        strncpy(cfg->db_host, host, sizeof(cfg->db_host) - 1);
        cfg->db_host[sizeof(cfg->db_host) - 1] = '\0';
    } else {
        strncpy(cfg->db_host, "localhost", sizeof(cfg->db_host) - 1);
    }

    const char *chunk_str = getenv("CHUNK_SIZE");
    if (chunk_str != NULL) {
        long val = strtol(chunk_str, NULL, 10);
        cfg->chunk_size = (val > 0 && val <= MAX_CHUNK) ? (size_t)val : 4096;
    } else {
        cfg->chunk_size = 4096;
    }
    return 0;
}

/* Safe allocation - fixed size to avoid overflow analysis complexity */
static void *alloc_safe(void) {
    return malloc(1024);
}

/* Safe format - literal only */
static void log_message(const char *msg) {
    printf("Log: %s\n", msg);
}

int main(void) {
    Config cfg;
    if (load_config(&cfg) != 0) {
        return 1;
    }

    char *buf = alloc_safe();
    if (buf == NULL) {
        return 1;
    }

    if (fgets(buf, 1024, stdin) != NULL) {
        log_message(buf);
    }
    free(buf);
    return 0;
}
