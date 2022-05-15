#include "protocol_funcs.h"


unsigned char* text1 = (unsigned char*)"I'M TIRED OF WRITING THESE LABS.(AND THE ASSEMBLER WITH THE AISD TOO)\00";
int mode_key_bytes[4] = {24, 16, 24, 32};
int mode_iv_bytes[4] = {8, 16, 16, 16};
int mode_hmac_bytes[2] = {16, 20};

void(*fhmac[2])(unsigned char *, size_t, unsigned char *, size_t, unsigned char *) = {hmac_md5, hmac_sha1};

static void (*fdecipher[4])(unsigned char *, size_t,
			       unsigned char *, unsigned char *,
				unsigned char *) = {des3_cbc_decrypt, aes128_cbc_decrypt,
        aes192_cbc_decrypt, aes256_cbc_decrypt};


static void (*fcipher[4])(unsigned char *, size_t,
			       unsigned char *, unsigned char *,
				unsigned char *) = {des3_cbc_encrypt, aes128_cbc_encrypt,
        aes192_cbc_encrypt, aes256_cbc_encrypt};



static void des3_cbc_decrypt(unsigned char *in, size_t in_len,
			       unsigned char *iv, unsigned char *key, unsigned char *out) {
	DES_cblock key1, key2, key3;
	DES_key_schedule ks1, ks2, ks3;
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);

	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_DECRYPT);
}


static void aes128_cbc_decrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out) {
	AES_KEY akey;
	AES_set_decrypt_key(key, 128, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}


static void aes192_cbc_decrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out) {
	AES_KEY akey;
	AES_set_decrypt_key(key, 192, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}


static void aes256_cbc_decrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key,
				    unsigned char *out) {
	AES_KEY akey;
	AES_set_decrypt_key(key, 256, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}


static void des3_cbc_encrypt(unsigned char *in, size_t in_len,
			       unsigned char *iv, unsigned char *key, unsigned char *out) {
	DES_cblock key1, key2, key3;
	DES_key_schedule ks1, ks2, ks3;
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);

	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_ENCRYPT);
}


static void aes128_cbc_encrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out) {
	AES_KEY akey;
	AES_set_encrypt_key(key, 128, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}


static void aes192_cbc_encrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key, unsigned char *out) {
	AES_KEY akey;
	AES_set_encrypt_key(key, 192, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}


static void aes256_cbc_encrypt(unsigned char *in, size_t in_len,
				    unsigned char *iv, unsigned char *key,
				    unsigned char *out) {
	AES_KEY akey;
	AES_set_encrypt_key(key, 256, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}


void hmac_md5(unsigned char *text,
    size_t text_len, unsigned char *key, size_t key_len, unsigned char *md)
{
	static unsigned char m[16];
	MD5_CTX context;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	unsigned char tk[16];
	int i;

	if (md == NULL)
		md = m;


	if (key_len > 64) {
		MD5_CTX tctx;

		MD5_Init(&tctx);
		MD5_Update(&tctx, key, key_len);
		MD5_Final(tk, &tctx);

		key = tk;
		key_len = 16;
	}

	memset(k_ipad, 0x36, sizeof k_ipad);
	memset(k_opad, 0x5c, sizeof k_opad);

	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}

	MD5_Init(&context);
	MD5_Update(&context, k_ipad, 64);
	MD5_Update(&context, text, text_len);
	MD5_Final(md, &context);
	MD5_Init(&context);
	MD5_Update(&context, k_opad, 64);
	MD5_Update(&context, md, 16);
	MD5_Final(md, &context);

	//return md;
}


void hmac_sha1(const unsigned char *text,
    size_t text_len, const unsigned char *key, size_t key_len,
    unsigned char *md)
{
	static unsigned char m[20];
	SHA_CTX context;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	unsigned char tk[20];
	int i;

	if (md == NULL)
		md = m;


	if (key_len > 64) {
		SHA_CTX tctx;

		SHA1_Init(&tctx);
		SHA1_Update(&tctx, key, key_len);
		SHA1_Final(tk, &tctx);
		key = tk;
		key_len = 20;
	}



	memset(k_ipad, 0x36, sizeof k_ipad);
	memset(k_opad, 0x5c, sizeof k_opad);


	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}

	SHA1_Init(&context);
	SHA1_Update(&context, k_ipad, 64);
	SHA1_Update(&context, text, text_len);
	SHA1_Final(md, &context);

	SHA1_Init(&context);
	SHA1_Update(&context, k_opad, 64);
	SHA1_Update(&context, md, 20);
	SHA1_Final(md, &context);
	//return md;
}


unsigned char* generate_rand(int length){
  unsigned char* res = (unsigned char*)malloc(length * sizeof(unsigned char));
  unsigned char* r = res;
	srand(time(NULL));
  for (int i = 0; i < length; i++){
    res[i] = (rand() * rand()%(256));
    r++;
  }
  return res;
}


char* fgetstr (FILE* fd) {
	char* ptr = (char*)malloc(1);
	char buf[81];
	int n, len = 0;
	*ptr = '\0';
	do {
		n = fscanf(fd, "%80[^\n]", buf);
		if (n == 0) {
			fscanf(fd, "%*c");
		}
		else if (n>0){
			len += strlen(buf);
			ptr = (char*)realloc(ptr, len + 2);
			int k = strlen(buf);
			int l = strlen(ptr) + k + 1;
			strncat(ptr,buf, k);
		}
	} while (n > 0);
	return ptr;
}


void cipher(int mode_hash, int mode_cipher, unsigned char* password,
						unsigned char* iv, unsigned char* nonce, char* file_name, char*input){
	unsigned char* key = (unsigned char*)calloc(1, sizeof(unsigned char));
  unsigned char* hmac = (unsigned char*)malloc(mode_hmac_bytes[mode_hash]);
  unsigned char* new_text = (unsigned char*)calloc(8, sizeof(unsigned char));
  unsigned char* iv1 = (unsigned char*)calloc(1, sizeof(unsigned char));
	unsigned char* nonce1 = (unsigned char*)calloc(1, sizeof(unsigned char));
	unsigned char* zeroes = NULL;
	FILE* fd;
	fd = fopen(input, "r");
	unsigned char* text1 = (unsigned char*)fgetstr(fd);
	int text_len = strlen((char*)text1);
	unsigned char* cipher_text = (unsigned char*)calloc(text_len, sizeof(unsigned char));
	fclose(fd);
	if (nonce == NULL){
		nonce = (unsigned char*)calloc(nonce, 1);
		nonce = generate_rand(64);
	}
	if (iv == NULL) {
		iv = (unsigned char*)calloc(iv, 1);
		iv = generate_rand(mode_iv_bytes[mode_cipher]);
	}
  iv1 = concatenate(iv1, iv, 0, mode_iv_bytes[mode_cipher]);
	nonce1 = concatenate(nonce1, nonce, 0, 64);
  new_text = concatenate(new_text, text1, 8, strlen((char*)text1));
	int text_len1 = text_len + 8;
	if ((text_len + 8) % mode_key_bytes[mode_cipher] != 0) {
		text_len1 += mode_key_bytes[mode_cipher] - ((text_len + 8) % mode_key_bytes[mode_cipher]);
		zeroes = (unsigned char*)calloc(mode_key_bytes[mode_cipher] - ((text_len + 8) % mode_key_bytes[mode_cipher]), sizeof(unsigned char));
		new_text = concatenate(new_text, zeroes, text_len + 8, text_len1 - text_len - 8);
	}
  fhmac[mode_hash](nonce, 64, password, 4, hmac);
	int key_len = 0;
  key = concatenate(key, hmac, key_len, mode_hmac_bytes[mode_hash]);
	key_len += mode_hmac_bytes[mode_hash];
  while(key_len < mode_key_bytes[mode_cipher]) {
    fhmac[mode_hash](hmac, mode_hmac_bytes[mode_hash], password, 4, hmac);
    key = concatenate(key, hmac, key_len, mode_hmac_bytes[mode_hash]);
		key_len += mode_hmac_bytes[mode_hash];
  }
  if (key_len > mode_key_bytes[mode_cipher]) {
    key[mode_key_bytes[mode_cipher]] = '\0';
  }
  //char* file_name = construct_fname(mode_hash, mode_cipher, password);
	//FILE* fd;
  fd = fopen(file_name, "w+b");
  char* str = "ENC";
  fwrite(str, sizeof(char), 3, fd);
  fwrite(&mode_hash, sizeof(unsigned char), 1, fd);
  fwrite(&mode_cipher, sizeof(unsigned char), 1, fd);
  fwrite(nonce, sizeof(unsigned char), 64, fd);
  fwrite(iv, sizeof(unsigned char), mode_iv_bytes[mode_cipher], fd);
	fcipher[mode_cipher](new_text, text_len + 8, iv, key, cipher_text);
	fwrite(cipher_text, sizeof(unsigned char), text_len + 8, fd);
	//fclose(fd);
	free(key);
	free(hmac);
	free(new_text);
	free(cipher_text);
	free(iv);
}



void hexchar (unsigned int num, unsigned char** str) {
  unsigned char s= 0;
  *str = (unsigned char*)malloc(4);
  for (int i = 0; i < 4; i++) {
    (*str)[3 - i] = num % 256;
    num = num / 256;
  }
}


unsigned char* decrypt (char* file_name, unsigned char* password, char* output) {
	 unsigned char* nonce = (unsigned char*)calloc(64, sizeof(unsigned char));
   unsigned char* iv = NULL;
   unsigned char* text = NULL;
   int mode_hash = 0, mode_cipher = 0;
   int a = -1;
   unsigned int result = 0;
	 unsigned char* zeroes = NULL;
   int text_len1 = 0;
   analyse_file (file_name, &mode_hash, &mode_cipher, &nonce, &iv, &text, &text_len1);
	 unsigned char* key = (unsigned char*)calloc(1, sizeof(unsigned char));
   unsigned char* hmac = (unsigned char*)malloc(mode_hmac_bytes[mode_hash]);
   unsigned char* open_text = (unsigned char*)calloc(text_len1, sizeof(unsigned char));
	 unsigned char* iv1 = (unsigned char*)calloc(1, sizeof(unsigned char));
   iv1 = concatenate(iv1, iv, 0, mode_iv_bytes[mode_cipher]);
	 int text_len = text_len1;
	 if ((text_len1) % mode_key_bytes[mode_cipher] != 0) {
			 text_len += mode_key_bytes[mode_cipher] - (text_len1) % mode_key_bytes[mode_cipher];
			 zeroes = (unsigned char*)calloc(mode_key_bytes[mode_cipher] - ((text_len1) % mode_key_bytes[mode_cipher]), sizeof(unsigned char));
			 text = concatenate(text, zeroes, text_len1, text_len - text_len1);
		 }
	 int key_len = 0;
	 fhmac[mode_hash](nonce, 64, password, 4, hmac);
   key = concatenate(key, hmac, 0, mode_hmac_bytes[mode_hash]);
	 key_len+=mode_hmac_bytes[mode_hash];
   while(key_len < mode_key_bytes[mode_cipher]) {
     fhmac[mode_hash](hmac, mode_hmac_bytes[mode_hash], password, 4, hmac);
     key = concatenate(key, hmac, key_len, mode_hmac_bytes[mode_hash]);
		 key_len+=mode_hmac_bytes[mode_hash];
   }
   if (key_len > mode_key_bytes[mode_cipher]) {
     key[mode_key_bytes[mode_cipher]] = '\0';
   }

	 fdecipher[mode_cipher](text, text_len, iv1, key, open_text);
	 FILE* fd;
	 fd = fopen(output, "wb");
	 fwrite(open_text + 8, sizeof(unsigned char), text_len1 - 8, fd);
 	 fclose(fd);
	 //free(iv1);
	 free(key);
	 free(hmac);
   return open_text;
	 }


void analyse_file (char* file_name, int* mode_hash, int* mode_cipher, unsigned char** nonce,
   unsigned char** iv, unsigned char** text, int* text_len) {
  FILE* fd;
  int offset = 0, size = 0;
  fd = fopen(file_name, "rb");
  fseek(fd, 3, SEEK_SET);
  fread(mode_hash, sizeof(unsigned char), 1, fd);
  fread(mode_cipher, sizeof(unsigned char), 1, fd);
  fread(*nonce, sizeof(unsigned char), 64, fd);
  *iv = (unsigned char*)malloc(mode_iv_bytes[*mode_cipher]);
  fread(*iv, sizeof(unsigned char), mode_iv_bytes[*mode_cipher], fd);
  offset = ftell(fd);
  fseek(fd, 0L, SEEK_END);
  size = ftell(fd);
  fseek(fd, offset, SEEK_SET);
  *text = (unsigned char*)malloc(size - offset);
  fread(*text, sizeof(unsigned char), size - offset, fd);
  *text_len = size - offset;
}


int checker_symbol(unsigned char symb, int position){
  char* first = "ENC";
  if (position < 3){
    return symb == first[position] ? 0 : WRONG_VALUE;
  }
  else if (position == 3){
    return (symb == 0 || symb == 1) ? 0 : WRONG_VALUE;
  }
  else if (position == 4){
    return (symb >= 0 && symb <= 4) ? 0 : WRONG_VALUE;
  }
  else{
    return (position < 5 + 64 + 16 + 4096) ? 0 : WRONG_VALUE;
  }
}


int file_checker(char* file_name){
  FILE* fd;
  int size = 0, err;
  fd = fopen(file_name, "r");
  if (fd == NULL){
		printf("no such file\n");
    return WRONG_VALUE;
  }
  unsigned char symb = 0;
  fseek(fd, 0L, SEEK_END);
  size = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  for (int i = 0; i < size; i++) {
    fread(&symb, sizeof(unsigned char), 1, fd);
    err = checker_symbol(symb, i);
    if (err == WRONG_VALUE){
			printf("i =  %d WRONG symb\n", i);
      return WRONG_VALUE;
    }
  }
  return 0;
}


int analyse_input_crypt (int argc, char** argv, unsigned char** iv, unsigned char** nonce, int* mode_cipher,
int* mode_hash, int* crypt_mode, unsigned char** pass, char** input_filename, char** output_filename) {
  const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"nonce", required_argument, NULL, 'n'},
		{"alg", required_argument, NULL, 'a'},
		{"hmac", required_argument, NULL, 'm'},
    {"enc", no_argument, NULL, 'e'},
    {"dec", no_argument, NULL, 'd'},
    {"pass", required_argument, NULL, 'p'},
    {"iv", required_argument, NULL, 'i'},
    {"input", required_argument, NULL, 'f'},
		{"output", required_argument, NULL, 'o'},
    {NULL, 0, NULL, 0}
  };
	int args_here = 0, pass_here = 0;
  const char* short_options = "hvn:a:m:edp:i:f:o:";
  int wrong = 1, err = 0;
	char str[2];
  while (optind < argc - 1 || optind < 2){
    int cc = getopt_long(argc, argv, short_options, long_options, NULL);
    char c = cc;
    switch (c) {
      case 'h': {
        printf("-v, --version for software version\n");
        printf("-n, --nonce=[value] for enter nonce (enc)\n");
        printf("-a, --alg=[value] for enter algo mode\n");
        printf("-m, --hmac=[value] for enter hmac mode\n");
				printf("-e, --enc for enctypt mode\n");
				printf("-d, --dec for decrypt mode\n");
        printf("-p, --pass=[value] for pass init\n");
        printf("-i, --iv=[value] for initialization vector\n");
        printf("-f, --input=[value] for input file\n");
				printf("-o, --output=[value] for output file\n");
				wrong = 0;
				continue;
      }
      case 'v':{
        printf("Software version 1.0\n");
				wrong = 0;
				continue;
      }
      case 'n':{
        if (strlen(optarg) != 132){
        	return WRONG_VALUE;
				}
				else {
					*nonce = (unsigned char*)malloc(64);
					for(int i = 0; i < 64; i++){
						str[0] = optarg[i * 2];
						str[1] = optarg[i * 2 + 1];
						(*nonce)[i] = hex_from_str(str, &err);
						if(err == WRONG_VALUE){
							return err;
						}
					}
				}
				args_here = 1;
      	continue;
      }
      case 'i':{
				if (strlen(optarg) != mode_iv_bytes[*mode_cipher] * 2){
					printf("WRONG IV LEN\n");
        	return WRONG_VALUE;
				}
				else {
					*iv = (unsigned char*)malloc(mode_iv_bytes[*mode_cipher]);
					for(int i = 0; i < mode_iv_bytes[*mode_cipher]; i++){
						str[0] = optarg[i * 2];
						str[1] = optarg[i * 2 + 1];
						(*iv)[i] = hex_from_str(str, &err);
						if(err == WRONG_VALUE){
							printf("WRONG IV\n");
							return err;
						}
					}
				}
				args_here = 1;
      	continue;
      }
      case 'a':{
				*mode_cipher = check_inarray(optarg, cipher_modes, 4);
				if (*mode_cipher == WRONG_VALUE){
					printf("WRONG CIPHER MODE\n");
					return WRONG_VALUE;
        }
				args_here = 1;
        continue;
      }
      case 'm':{
				*mode_hash = check_inarray(optarg, hash_modes, 2);
				if (*mode_hash == WRONG_VALUE){
				printf("WRONG MODE HASH\n");
				return WRONG_VALUE;
        }
				args_here = 1;
        continue;
      }
      case 'e':{
				*crypt_mode = ENCRYPT;
        continue;
      }
			case 'd':{
				*crypt_mode = DECRYPT;
        continue;
      }
			case 'p':{
        if (strlen(optarg) != 8){
					printf("WRONG PASS LEN\n");
        	return WRONG_VALUE;
				}
				else {
					*pass = (unsigned char*)malloc(4);
					for(int i = 0; i < 4; i++){
						str[0] = optarg[i * 2];
						str[1] = optarg[i * 2 + 1];
						(*pass)[i] = hex_from_str(str, &err);
						if(err == WRONG_VALUE){
							printf("WRONG PASS\n");
							return err;
						}
					}
				}
				pass_here = 1;
      	continue;
      }
      case 'f':{
				int len = strlen(optarg);
				*input_filename = (char*)malloc(len + 1);
				(*input_filename)[len] = '\0';
				strcpy(*input_filename, optarg);
				continue;
      }
			case 'o':{
				int len = strlen(optarg);
				*output_filename = (char*)malloc(len + 1);
				(*output_filename)[len] = '\0';
				strcpy(*output_filename, optarg);
				continue;
			}
      case -1:{
				argc--;
				optind++;
				break;
      }
    }
  }
	if (wrong == 0){
		wrong = 0;
	}
	else if (pass_here == 0) {
		printf("NO PASSWORD\n");
		wrong = -1;
	}
	else if (*crypt_mode == DECRYPT && args_here == 1) {
		printf("DECRYPT DEFAULT\n");
		wrong = -1;
	}
	else if (*pass == NULL || *crypt_mode == -1 ||
	*input_filename == NULL || *output_filename == NULL) {
		printf("NO ONE OF ARGS\n");
		wrong = -1;
	}
	if(wrong == -1){
		printf("WRONG INPUT END\n");
		return WRONG_VALUE;
	}
	else if (wrong == 0)
		return 1;
	else
  	return 0;
}
