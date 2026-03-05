/* HARD: Realistic enterprise-style code with multiple vulnerabilities.
 * Simulates: config loading, data processing, logging - all with issues.
 * Expected: multiple rules (buffer-overflow, format-string, hardcoded-secrets,
 *           unsafe-functions, integer-overflow, null-checks)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDS 1000

/* Config struct - hardcoded credentials */
struct AppConfig {
    const char *db_password;
    const char *api_secret;
    size_t chunk_size;
};

static struct AppConfig g_config = {
    .db_password = "P@ssw0rd#DB",
    .api_secret = "sk-prod-abc123xyz",
    .chunk_size = 4096,
};

/* Process record - unchecked allocation, no null check */
void process_record(size_t idx, size_t count) {
    size_t alloc_size = idx * count;   /* integer_overflow: can overflow */
    char *buf = malloc(alloc_size);
    buf[0] = 0;   /* null_checks: no NULL check */
    free(buf);
}

/* Build output - user controls format string */
void build_output(char *out, const char *user_fmt) {
    sprintf(out, user_fmt, "value");   /* format-string: user_fmt is user-controlled */
}

/* Log with user-controlled format */
void app_log(const char *fmt, const char *msg) {
    printf(fmt, msg);   /* format-string: user format */
}

/* Legacy input - gets */
void read_legacy_input(char *buf) {
    gets(buf);   /* unsafe-functions, buffer-overflow */
}

int main(int argc, char **argv) {
    char input[64];
    read_legacy_input(input);

    app_log("Msg: %s\n", input);
    process_record(1 << 20, 1 << 20);

    printf("Config: %s\n", g_config.db_password);
    return 0;
}
