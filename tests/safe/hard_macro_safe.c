/* HARD: Safe macro usage - macros expand to bounded functions.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUF_SIZE 64

#define READ_LINE_SAFE(buf, size) \
    (fgets((buf), (int)(size), stdin) != NULL)

#define COPY_SAFE(dst, src, size) do { \
    strncpy((dst), (src), (size) - 1); \
    (dst)[(size) - 1] = '\0'; \
} while (0)

#define SNPRINTF_SAFE(buf, size, fmt, ...) \
    snprintf((buf), (size), (fmt), __VA_ARGS__)

void process_input(void) {
    char line[BUF_SIZE];
    if (READ_LINE_SAFE(line, sizeof(line))) {
        printf("Read: %s", line);
    }
}

void copy_data(void) {
    char dst[32];
    const char *src = "hello";
    COPY_SAFE(dst, src, sizeof(dst));
    printf("%s\n", dst);
}

void format_message(void) {
    char buf[128];
    const char *user = "alice";
    SNPRINTF_SAFE(buf, sizeof(buf), "User: %s\n", user);
    printf("%s", buf);
}

int main(void) {
    process_input();
    copy_data();
    format_message();
    return 0;
}
