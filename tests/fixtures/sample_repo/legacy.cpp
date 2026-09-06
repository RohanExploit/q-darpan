// Fixture: C++ translation unit using the same C APIs. Exercises the cpp
// grammar sharing the C rule pack.
#include <openssl/evp.h>
#include <string>

namespace legacy {

int weak_stream(EVP_CIPHER_CTX *ctx, const unsigned char *key)
{
    // RC4 is prohibited in TLS by RFC 7465.
    return EVP_EncryptInit_ex(ctx, EVP_rc4(), nullptr, key, nullptr);
}

int weak_hash(EVP_MD_CTX *ctx)
{
    return EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
}

}  // namespace legacy
