#!/bin/bash
set -e

# Validate argument thresholds
if [ "$#" -ne 3 ]; then
    echo "========================================================================="
    echo " Heimdal ASN.1 Compliance Test Gate"
    echo "========================================================================="
    echo "Usage: docker run --rm -v \$(pwd):/workspace <image_name> <schema.asn> <TopLevelType> <test_vector.der>"
    echo ""
    echo "Example: docker run --rm -v \$(pwd):/workspace asn1-gate rfc9935.asn KemPublicKey test.der"
    echo "========================================================================="
    exit 1
fi

SCHEMA_FILE=$1
TOP_TYPE=$2
DER_FILE=$3
PREFIX="compiled_schema"

# 1. Compile the schema. --one-code-file is required so a single combined
#    source file is produced (asn1_${PREFIX}.x) instead of one file per
#    ASN.1 type -- otherwise every type in the schema would need to be
#    discovered and compiled separately, and the script would only ever
#    build the top-level type's own file, failing to link against any
#    type it references internally.
echo "==> [Step 1/4] Parsing & compiling schema: ${SCHEMA_FILE}..."
asn1_compile --one-code-file "${SCHEMA_FILE}" "${PREFIX}"

# 2. asn1_compile emits .x/.hx files (a Heimdal build-system convention
#    for avoiding spurious rebuilds when content is unchanged), not .c/.h
#    directly, and the header has NO "asn1_" prefix -- only the combined
#    source file does. Rename explicitly rather than assuming the .c/.h
#    names the original script guessed.
cp "asn1_${PREFIX}.x" "asn1_${PREFIX}.c"
cp "${PREFIX}.hx" "${PREFIX}.h"
cp "${PREFIX}-priv.hx" "${PREFIX}-priv.h"

# 3. Generate the C test harness.
echo "==> [Step 2/4] Injecting type context into C validation harness..."
cat << EOF > verify_der.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "${PREFIX}.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Missing target binary DER file path.\\n");
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: Unable to open DER file %s\\n", argv[1]);
        return 2;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buffer = malloc(fsize);
    if (!buffer) {
        fprintf(stderr, "Error: Out of memory buffer allocation.\\n");
        fclose(f);
        return 2;
    }

    size_t read_bytes = fread(buffer, 1, fsize, f);
    fclose(f);
    (void)read_bytes;

    ${TOP_TYPE} message;
    size_t decoded_size = 0;

    int result = decode_${TOP_TYPE}(buffer, fsize, &message, &decoded_size);
    free(buffer);

    if (result == 0) {
        printf(" SUCCESS: Python wire bytes strictly align with the formal ASN.1 layout.\\n");
        free_${TOP_TYPE}(&message);
        return 0;
    } else {
        fprintf(stderr, " FAILURE: Structural mismatch or constraint violation detected.\\n");
        fprintf(stderr, "          Heimdal Error Code: %d\\n", result);
        return 1;
    }
}
EOF

# 4. Build the validator.
#
# krb5-config.heimdal does NOT accept "asn1" as a library name -- its
# recognized set is krb5/gssapi/kadm-client/kadm-server/kafs only, and
# silently prints "unknown option" rather than erroring loudly. Use the
# known Heimdal include/lib paths directly instead.
#
# asn1_compile's generated code (both the default and --template modes)
# includes <asn1-template.h>, which is NOT shipped by the heimdal-multidev
# -dev package on Debian/Ubuntu (confirmed via apt-file search across the
# whole archive: zero packages provide it). The five runtime functions it
# declares (_asn1_decode_top, _asn1_encode, _asn1_free_top, _asn1_copy_top,
# _asn1_length) ARE already present in the installed libasn1.so, though --
# so only the header itself needs vendoring, not an implementation. It's
# copied in here from Heimdal's own source tree, pinned to the exact git
# commit this Debian package build is derived from (28daf24, matching the
# installed heimdal-multidev version string
# 7.8.git20221117.28daf24+dfsg-5ubuntu3) to avoid ABI/API drift against a
# different Heimdal version. If the base image's heimdal-multidev version
# ever changes, re-fetch vendor/asn1-template.h from the matching commit.
echo "==> [Step 3/4] Building validator against the Heimdal ASN.1 runtime..."
gcc -I/usr/include/heimdal -I/vendor -I. verify_der.c "asn1_${PREFIX}.c" \
    -L/usr/lib/x86_64-linux-gnu/heimdal -lasn1 -lroken \
    -o der_validator

# 5. Perform strict wire verification.
echo "==> [Step 4/4] Executing byte-verification check on: ${DER_FILE}..."
export LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu/heimdal:${LD_LIBRARY_PATH}"
./der_validator "${DER_FILE}"
