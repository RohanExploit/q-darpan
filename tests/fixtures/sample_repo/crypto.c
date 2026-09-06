/* Fixture: representative OpenSSL usage in C.
   Every call here is a labelled positive in expected.json. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#define RSA_BITS 2048

int setup_cipher(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv)
{
    return EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
}

int legacy_cipher(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv)
{
    /* Deliberately weak: 3DES is disallowed by NIST SP 800-131A after 2023. */
    return EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
}

int digest_modern(EVP_MD_CTX *ctx)
{
    return EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
}

int digest_legacy(EVP_MD_CTX *ctx)
{
    /* Deliberately broken: practical MD5 collisions since 2004. */
    return EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
}

RSA *make_rsa_key(BIGNUM *e)
{
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    return rsa;
}

EC_KEY *make_ec_key(void)
{
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
