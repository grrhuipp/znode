/// aws-lc C API bindings via @cImport.
/// Provides OpenSSL-compatible API (aws-lc is a BoringSSL fork).
pub const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/aes.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/md5.h");
    @cInclude("openssl/hmac.h");
    @cInclude("openssl/hkdf.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/err.h");
    // TLS
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/rsa.h");
});
