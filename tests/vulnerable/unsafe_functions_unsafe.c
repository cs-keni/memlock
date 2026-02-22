/* Expected rule results for this file:
 * - unsafe_functions: FAIL (should report findings for gets, strcpy, sprintf, scanf)
 * - use_after_free: PASS (no use-after-free)
 * - buffer_overflow: PASS (no explicit index overflow; gets/strcpy are covered by unsafe_functions)
 * - memory_management: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    char name[16];
    char small[8];
    char msg[32];

    /* Classic unsafe input: gets() */
    gets(name);                 /* unsafe_functions should flag this */

    /* Unsafe copy: strcpy with no bounds check */
    strcpy(small, name);        /* unsafe_functions should flag this */

    /* Unsafe formatting: sprintf with no bounds check */
    sprintf(msg, "Hello %s", name);  /* unsafe_functions should flag this */

    /* scanf with unbounded %s */
    char other[16];
    scanf("%s", other);         /* unsafe_functions should flag this */

    printf("%s %s\n", small, msg);
    return 0;
}

