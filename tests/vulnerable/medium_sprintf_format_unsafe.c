/* MEDIUM: sprintf/fprintf with non-literal format - format string vuln.
 * Expected: format-string, unsafe-functions (sprintf), buffer-overflow
 */

#include <stdio.h>
#include <string.h>

void log_message(const char *fmt, const char *msg) {
    char buf[256];
    sprintf(buf, fmt, msg);   /* fmt is user-controlled - format string vuln */
    fprintf(stderr, "%s\n", buf);
}

void build_path(char *out, const char *user_dir, const char *user_file) {
    char fmt[64];
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
        return;
    }
    sprintf(out, fmt, user_dir, user_file);   /* User controls format */
}

int main(void) {
    char path[128];
    log_message("Message: %s", "hello");
    build_path(path, "/home", "file.txt");
    return 0;
}
