/* Build-time helper, host-side only (not part of any seL4 PD image): given an ML-KEM-768 private
 * key PEM, write the raw FIPS-203 encapsulation key (the public key, "ek", 1184 bytes for
 * ML-KEM-768) to stdout. Used by scripts/build-sel4.sh to produce
 * examples/press-site/pqkey.bin, the public asset a browser fetches and feeds to
 * noble-post-quantum's ml_kem768.encapsulate(). Links the project's own host-side OpenSSL 3.6.1
 * build (third_party/openssl-install), the same one used for every other OpenSSL CLI/test
 * operation this project runs on the host. See docs/QEDOS_PRESS_PQ_WRAP.md.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s priv.pem > pub.raw\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) { fprintf(stderr, "pq-dump-pubkey: failed to read private key\n"); return 1; }
    unsigned char buf[4096];
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &len) != 1) {
        fprintf(stderr, "pq-dump-pubkey: EVP_PKEY_get_octet_string_param(pub) failed\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    fwrite(buf, 1, len, stdout);
    fprintf(stderr, "pq-dump-pubkey: wrote %zu raw public key bytes\n", len);
    EVP_PKEY_free(pkey);
    return 0;
}
