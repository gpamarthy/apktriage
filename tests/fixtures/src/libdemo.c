/* Benign native fixture for apktriage tests.
 * The strings are FAKE documentation-range values (RFC 5737 / RFC 7042),
 * planted so the native string sweep + secret/indicator scanners have
 * deterministic data. references system()/getenv() so the ELF import table
 * exposes a "suspicious import" for native.py to flag. Not malicious. */
#include <stdlib.h>
#include <string.h>

const char *c2 = "http://203.0.113.45/native_gate";
const char *key = "native_secret_AKIAIOSFODNN7EXAMPLE";

int run_payload(const char *cmd) {
    char buf[256];
    const char *p = getenv("PATH");
    if (p) {
        strncpy(buf, p, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    }
    return system(cmd);
}
