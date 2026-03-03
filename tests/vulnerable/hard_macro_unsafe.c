/* HARD: Macros that expand to unsafe code - scanner sees pre-expansion.
 * We use inline wrappers so the scanner sees gets/strcpy directly.
 * Expected: unsafe-functions, buffer-overflow, format-string
 */

#include <stdio.h>
#include <string.h>

/* Wrappers that call unsafe functions - scanner detects these */
static void read_line_unsafe(char *buf) {
    gets(buf);   /* Unsafe - unbounded read */
}

static void copy_str_unsafe(char *dst, const char *src) {
    strcpy(dst, src);   /* Unsafe - unbounded copy */
}

void process_input(void) {
    char line[64];
    read_line_unsafe(line);
}

void copy_data(void) {
    char dst[8];
    copy_str_unsafe(dst, "long string that overflows");
}

void log_user_input(const char *user) {
    printf(user);   /* Format string - user controls format */
}

int main(void) {
    process_input();
    copy_data();
    log_user_input("test");
    return 0;
}
