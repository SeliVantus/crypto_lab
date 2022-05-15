#ifndef PROTOCOL_FUNCS
#define PROTOCOL_FUNCS


#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include "generator.h"

#define TEXT_LEN 60
#define ENCRYPT -11
#define DECRYPT -12


int mode_key_bytes[4];
int mode_iv_bytes[4];


void hmac_md5(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md);

void hmac_sha1(const unsigned char *text, size_t text_len, const unsigned char *key, size_t key_len, unsigned char *md);

static void des3_cbc_decrypt(unsigned char *in, size_t in_len,
			       unsigned char *iv, unsigned char *key, unsigned char *out);

static void aes128_cbc_decrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out);

static void aes192_cbc_decrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out);

static void aes256_cbc_decrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out);

static void des3_cbc_encrypt(unsigned char *in, size_t in_len,
			       unsigned char *iv, unsigned char *key, unsigned char *out);

static void aes128_cbc_encrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out);

static void aes192_cbc_encrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out);

static void aes256_cbc_encrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out);

void hmac_sha1(const unsigned char *text,
    size_t text_len, const unsigned char *key, size_t key_len,
    unsigned char *md);

void hmac_md5(unsigned char *text,
    size_t text_len, unsigned char *key, size_t key_len, unsigned char *md);

void generator (int mode_hash, int mode_cipher, unsigned char* password);

unsigned char* generate_rand(int length);

void(*fhmac[2])(unsigned char *, size_t, unsigned char *, size_t, unsigned char *);

static void (*fcipher[4])(unsigned char *, size_t,
			       unsigned char *, unsigned char *,
				unsigned char *);

static void (*fdecipher[4])(unsigned char *, size_t,
			       unsigned char *, unsigned char *,
				unsigned char *);

void to_file (int mode_hash, int mode_cipher, unsigned char* nonce,
              unsigned char* iv, char* file_name);

int file_checker(char* file_name);
void cipher(int mode_hash, int mode_cipher, unsigned char* password,
						unsigned char* iv, unsigned char* nonce, char* file_name, char* input);
unsigned char* decrypt (char* file_name, unsigned char* password, char* output);
int decipher (int mode_hash, int mode_cipher, unsigned char* nonce,
  unsigned char* iv, unsigned char* text, unsigned char* password, int text_len);
int cracker (char* file_name, int v);
void analyse_file (char* file_name, int* mode_hash, int* mode_cipher, unsigned char** nonce,
   unsigned char** iv, unsigned char** text, int* text_len);

int analyse_input_crypt (int argc, char** argv, unsigned char** iv, unsigned char** nonce, int* mode_cipher,
int* mode_hash, int* crypt_mode, unsigned char** pass, char** input_filename, char** output_filename);


#endif
