/* Mixed vulnerable example exercising multiple rules.
 *
 * Expected rule results for this file (once all rules are implemented):
 * - unsafe_functions: FAIL (uses gets)
 * - use_after_free: FAIL (pointer used after free)
 * - buffer_overflow: FAIL (out-of-bounds write on fixed-size buffer)
 * - memory_management: FAIL (leak and possible double-free if extended)
 * - hardcoded_secrets: FAIL (hardcoded API key / password string)
 * - integer_overflow: FAIL (suspicious arithmetic in malloc size)
 * - null_checks: FAIL (dereference of malloc result without NULL check)
 * - format_string: FAIL (printf with non-literal format string)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hardcoded secret: for future hardcoded_secrets rule */
static const char *API_KEY = "APIKEY-SECRET-1234567890";
static const char *PASSWORD = "P@ssw0rd!";

void buffer_overflow_example(void) {
    char buf[8];
    int i;

    /* Simple out-of-bounds write: i goes from 0 to 8 inclusive (9 writes) */
    for (i = 0; i <= 8; i++) {      /* buffer_overflow should flag this loop */
        buf[i] = 'A';
    }

    /* Classic unsafe input: gets() */
    gets(buf);                      /* unsafe_functions should flag this */
}

void memory_and_integer_example(int user) {
    size_t n = 1u << 30;            /* large value */
    size_t m = 16u;
    size_t total = n * m;           /* potential integer overflow */

    /* No NULL check before use: null_checks / integer_overflow rules later */
    char *p = (char *)malloc(total);
    if (!p) {
        /* Even though we check here, a more advanced rule might still treat
         * the combination of huge total and malloc as suspicious. */
        return;
    }

    p[0] = (char)user;

    /* Intentional leak: memory_management rule should eventually flag that
     * p is never freed. */
}

void use_after_free_example(void) {
    int *p = (int *)malloc(sizeof(int));
    if (!p) {
        return;
    }
    *p = 10;
    free(p);

    /* Use-after-free: dereference and write after free */
    *p = 20;                        /* use_after_free should flag this */
}

int main(int argc, char **argv) {
    char user_input[64];

    buffer_overflow_example();
    memory_and_integer_example(argc);
    use_after_free_example();

    /* Read untrusted data into user_input safely-ish for this demo */
    if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
        return 1;
    }

    /* Format string vulnerability: user-controlled format string */
    printf(user_input);             /* format_string rule should flag this */

    /* Print secrets to keep them referenced in the compiled binary */
    printf("Secrets: %s %s\n", API_KEY, PASSWORD);

    return 0;
}

