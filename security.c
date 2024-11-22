#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>

#define SECRET_SIZE 32
#define MAC_SIZE 32
#define IV_SIZE 16

EVP_PKEY* ec_priv_key = NULL;
EVP_PKEY* ec_peer_public_key = NULL;
EVP_PKEY* ec_ca_public_key = NULL;
size_t cert_size = 0;
uint8_t* certificate = NULL;
size_t pub_key_size = 0;
uint8_t* public_key = NULL;
uint8_t* secret = NULL;
uint8_t* enc_key = NULL;
uint8_t* mac_key = NULL;

void load_private_key(char* filename) {
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: invalid private key filename\n");
        return;
    }
    ec_priv_key = d2i_PrivateKey_fp(fp, NULL);
    if (ec_priv_key == NULL) {
        fprintf(stderr, "Error: invalid private key\n");
        return;
    }
    fclose(fp);
}

void load_peer_public_key(uint8_t* peer_key, size_t size) {
    BIO* bio = BIO_new_mem_buf(peer_key, size);
    ec_peer_public_key = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);
}

void load_ca_public_key(char* filename) {
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr,
                "Error: invalid certificate authority public key filename\n");
        return;
    }
    ec_ca_public_key = d2i_PUBKEY_fp(fp, NULL);
    if (ec_ca_public_key == NULL) {
        fprintf(stderr, "Error: invalid certificate authority public key\n");
        return;
    }
    fclose(fp);
}

void load_certificate(char* filename) {
    FILE* fp = fopen(filename, "r");
    uint8_t* cert;
    if (fp == NULL) {
        fprintf(stderr, "Error: invalid certificate filename\n");
        return;
    }
    fseek(fp, 0, SEEK_END);
    cert_size = ftell(fp);
    certificate = malloc(cert_size);
    fseek(fp, 0, 0);
    fread(certificate, cert_size, 1, fp);
    fclose(fp);
}

void generate_private_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &ec_priv_key);

    EVP_PKEY_CTX_free(pctx);
}

void derive_public_key() {
    pub_key_size = i2d_PUBKEY(ec_priv_key, &public_key);
}

void derive_secret() {
    size_t sec_size = SECRET_SIZE;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ec_priv_key, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, ec_peer_public_key);
    secret = malloc(sec_size);
    EVP_PKEY_derive(ctx, secret, &sec_size);

    EVP_PKEY_CTX_free(ctx);
}

void derive_keys() {
    EVP_KDF* kdf;
    EVP_KDF_CTX* kctx;
    OSSL_PARAM params[4];

    kdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    params[0] =
        OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t) 7);
    params[1] =
        OSSL_PARAM_construct_octet_string("key", secret, (size_t) SECRET_SIZE);
    params[2] = OSSL_PARAM_construct_octet_string("info", "enc", (size_t) 3);
    params[3] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(kctx, params);

    enc_key = malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, enc_key, SECRET_SIZE, NULL);

    params[2] = OSSL_PARAM_construct_octet_string("info", "mac", (size_t) 3);
    EVP_KDF_CTX_set_params(kctx, params);

    mac_key = malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, mac_key, SECRET_SIZE, NULL);

    EVP_KDF_CTX_free(kctx);
}

size_t sign(uint8_t* data, size_t size, uint8_t* signature) {
    size_t sig_size = 255;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_priv_key);
    EVP_DigestSignUpdate(mdctx, data, size);
    EVP_DigestSignFinal(mdctx, signature, &sig_size);

    EVP_MD_CTX_free(mdctx);
    return sig_size;
}

int verify(uint8_t* data, size_t size, uint8_t* signature, size_t sig_size,
           EVP_PKEY* authority) {
    int result;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, authority);
    EVP_DigestVerifyUpdate(mdctx, data, size);
    result = EVP_DigestVerifyFinal(mdctx, signature, sig_size);

    EVP_MD_CTX_free(mdctx);
    return result;
}

void generate_nonce(uint8_t* buf, size_t size) { RAND_bytes(buf, size); }

size_t encrypt_data(uint8_t* data, size_t size, uint8_t* iv, uint8_t* cipher) {
    int cipher_size;
    int padding_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    generate_nonce(iv, IV_SIZE);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv);
    EVP_EncryptUpdate(ctx, cipher, &cipher_size, data, size);
    EVP_EncryptFinal_ex(ctx, cipher + cipher_size, &padding_size);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_size + padding_size;
}

size_t decrypt_cipher(uint8_t* cipher, size_t size, uint8_t* iv,
                      uint8_t* data) {
    int data_size;
    int padding_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv);
    EVP_DecryptUpdate(ctx, data, &data_size, cipher, size);
    EVP_DecryptFinal_ex(ctx, data + data_size, &padding_size);

    EVP_CIPHER_CTX_free(ctx);

    return data_size + padding_size;
}

void hmac(uint8_t* data, size_t size, uint8_t* digest) {
    unsigned int mac_size = MAC_SIZE;
    HMAC(EVP_sha256(), mac_key, SECRET_SIZE, data, size, digest, &mac_size);
}

void derive_self_signed_certificate() {
    uint8_t sig[255];
    size_t sig_size = sign(public_key, pub_key_size, sig);

    cert_size = pub_key_size + sig_size + 9;
    certificate = malloc(cert_size);

    uint8_t* cert_type = certificate;
    *cert_type = 0xA0;

    uint16_t* cert_length = (uint16_t*) (certificate + 1);
    *cert_length = htons((uint16_t) (pub_key_size + sig_size + 6));

    uint8_t* pub_type = certificate + 3;
    *pub_type = 0xA1;

    uint16_t* pub_length = (uint16_t*) (certificate + 4);
    *pub_length = htons((uint16_t) pub_key_size);

    memcpy(certificate + 6, public_key, pub_key_size);

    uint8_t* sig_type = certificate + 6 + pub_key_size;
    *sig_type = 0xA2;

    uint16_t* sig_length = (uint16_t*) (certificate + 6 + pub_key_size + 1);
    *sig_length = htons((uint16_t) sig_size);

    memcpy(certificate + 6 + pub_key_size + 3, sig, sig_size);
}

void clean_up() {
    if (ec_priv_key)
        EVP_PKEY_free(ec_priv_key);
    if (ec_peer_public_key)
        EVP_PKEY_free(ec_peer_public_key);
    if (ec_ca_public_key)
        EVP_PKEY_free(ec_ca_public_key);
    if (certificate)
        free(certificate);
    if (public_key)
        free(public_key);
    if (secret)
        free(secret);
    if (enc_key)
        free(enc_key);
    if (mac_key)
        free(mac_key);
}
