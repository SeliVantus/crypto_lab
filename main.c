#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "debug.h"

#define SUCCESS 0
#define NO_KEY -1
#define NO_ARGS -2
#define WRONG_VALUE -3


const unsigned int subs[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
														0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
														0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
														0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
														0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
														0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
														0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
														0x51, 0xa3, 0x40, 0x9f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
														0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
														0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
														0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
														0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
														0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
														0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
														0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
														0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};


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


unsigned int hex_from_str (char* arg, int* err) {
  //printf("str hex = %s\n", arg);
  unsigned int res = 0;
  for (int i = 0; i < strlen(arg); i++){
    res *= 16;
    unsigned int a = 0;
    if (arg[i] >= '0' && arg[i] <= '9'){
      a = arg[i] - '0';
    }
    else if (arg[i] >= 'a' && arg[i] <= 'f'){
      a = arg[i] - 'a' + 10;
    }
    else{
      printf("%c --- wrong value\n", arg[i]);
      *err = WRONG_VALUE;
      return res;
    }
    res += a;
  }
  return res;
}


char* str_from_hex (char* block, unsigned int hex, long int size) {
	char* res;
  res = (char*)malloc(size + 1);
  int a = 0;
  for(int i = 1; i<size + 1; i++){
      a = hex % 16;
      if (a < 10)
			   res[size - i] = a + '0';
      else
        res[size - i] = 'a' + a -10;
		hex = hex >> 4;
	}
	res[size] = '\0';
  return res;
}


int analyse_input (int argc, char** argv, unsigned int* key, unsigned int* iv, int* crypt_mode, char* mode, int* debugger, int* timing) {
  const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"mode", required_argument, NULL, 'm'},
    {"enc", no_argument, NULL, 'e'},
    {"dec", no_argument, NULL, 'd'},
    {"key", required_argument, NULL, 'k'},
    {"iv", required_argument, NULL, 'i'},
    {"debug", no_argument, NULL, 'g'},
		{"time", no_argument, NULL, 't'},
    {NULL, 0, NULL, 0}
  };
	int key_here = 0, iv_here = 0;
  const char* short_options = "thvm:edk:i:g";
  int wrong = 1;
  while (optind < argc - 1 || optind < 2){
    int cc = getopt_long(argc, argv, short_options, long_options, NULL);
    char c = cc;
    switch (c) {
      case 'h': {
        printf("-v, --version for software version\n");
        printf("-m, --mode=[value] for mode choice. (ecb/cbc)\n");
        printf("-e, --enc flag for encryption mode\n");
        printf("-d, --dec flag for decryption mode\n");
        printf("-k, --key=[value] for key init\n");
        printf("-i, --iv=[value] for initialization vector\n");
        printf("-g, --debug for debug values\n");
				printf("-t, --time for timing\n");
				wrong = 0;
				continue;
      }
      case 'v':{
        printf("Software version 1.0\n");
				wrong = 0;
				continue;
      }
      case 'm':{
        if (strcmp(optarg, "ecb") == 0){
          *mode = 'e';
        }
        else if (strcmp(optarg, "cbc") == 0){
          *mode = 'c';
        }
				else if (strcmp(optarg, "ofb") == 0){
          *mode = 'o';
        }
        else{
          return WRONG_VALUE;
        }
        continue;
      }
      case 'e':{
        *crypt_mode = 1;
        continue;
      }
      case 'd':{
        *crypt_mode = 2;
        continue;
      }
      case 'k':{
        int err = 0;
				key_here = 1;
        *key = hex_from_str(optarg, &err);
        if (err == WRONG_VALUE){
					return WRONG_VALUE;
        }
        continue;
      }
      case 'i':{
				iv_here = 1;
        int err1 = 0;
        *iv = hex_from_str(optarg, &err1);
        if (err1 == WRONG_VALUE){
					return WRONG_VALUE;
        }
        continue;
      }
      case 'g':{
				*debugger = 1;
				continue;
      }
			case 't':{
				wrong = 0;
				*timing = 31;
				continue;
			}
      case -1:{
				argc--;
				optind++;
				break;
      }
    }
  }
	if (*mode == '\0' || *crypt_mode == 0 || key_here == 0 || (iv_here == 0 && (*mode == 'c' || *mode == 'o')))
		if(wrong == 1)
			return WRONG_VALUE;
		else
			return NO_ARGS;
  return 0;
}

unsigned int xor_key (unsigned int p, unsigned int k, int count) {
  p = p ^ k;
  return p;
}


unsigned int circular_shift (unsigned int p, int count) {
	p = (p >> 16 << 16) | (p << 16 >> 24) | (p << 24 >> 16);
  return p;
}


unsigned int circular_backshift (unsigned int p, int count) {
	p = (p >> 16 << 16) | (p << 16 >> 24) | (p << 24 >> 16);
  return p;
}


unsigned int s_block (unsigned int p, unsigned int*s_substitution, int count) {
	p = (s_substitution[p >> 24] << 24) + (s_substitution[p << 8 >> 24] << 16) + (s_substitution[p << 16 >> 24] << 8) + (s_substitution[p << 24 >> 24]);
  return p;
}


void load_subs_back (FILE* fd, unsigned int** s_substitution) {
  unsigned int* s = *s_substitution;
  char* str = (char*)malloc(3);
  str[2] = '\0';
  for (int i = 0; i < 256; i++){
    fgets(str, 3, fd);
    int err = 0;
    (*s_substitution)[hex_from_str(str, &err)] = i;
    unsigned int t = hex_from_str(str, &err);
    if (err == WRONG_VALUE){
    }
    s++;
  }
}


void load_subs_straight (FILE* fd, unsigned int** s_substitution) {
  unsigned int* s = *s_substitution;
  char* str = (char*)malloc(3);
  str[2] = '\0';
  for (int i = 0; i < 256; i++){
    fgets(str, 3, fd);
    int err = 0;
    (*s_substitution)[i] = hex_from_str(str, &err);
    if (err == WRONG_VALUE){
    }
    s++;
  }
}


void load_straight (char* file_name, char** p, unsigned int** s_substitution) {
  FILE* fd;
  fd = fopen(file_name, "r");
  load_subs_straight(fd, s_substitution);
  *p = fgetstr(fd);
  fclose(fd);
}


void load_back (char* file_name, char** p, unsigned int** s_substitution) {
  FILE* fd;
  fd = fopen(file_name, "r");
  load_subs_back(fd, s_substitution);
  *p = fgetstr(fd);
  fclose(fd);
}


unsigned int encryption_ecb_round (unsigned int* s_substitution, unsigned int p, unsigned int key, Debug* debug) {
  int count = 2;
  p = s_block(p, s_substitution, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = circular_shift(p, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = xor_key(p, key, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;

}


unsigned int decryption_ecb_round (unsigned int* s_substitution, unsigned int p, unsigned int key, Debug* debug) {
	int count = 2;
	p = xor_key(p, key, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	//printf("%d\n", debug->real_num);
	p = circular_shift(p, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	//printf("%d\n", debug->real_num);
  p = s_block(p, s_substitution, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	//printf("after s block %d\n", debug->real_num);
  return p;
}


unsigned int encryption_cbc_round (unsigned int* s_substitution, unsigned int p, unsigned int key, unsigned int iv, Debug* debug) {
  int count = 2;

	p = s_block(p, s_substitution, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = circular_shift(p, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  p = xor_key(p, key, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;
}


unsigned int decryption_cbc_round (unsigned int* s_substitution, unsigned int p, unsigned int key, unsigned int iv, Debug* debug) {
  int count = 2;
	p = xor_key(p, key, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	p = circular_backshift(p, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	p = s_block(p, s_substitution, count);
	debug->all[debug->real_num] = p;
	debug->real_num++;
	debug->all[debug->real_num] = p;
	debug->real_num++;
  return p;
}


void make_block (char** block, char* p, unsigned int* ptr, int* err, Debug* debug){
	strncpy(*block, p, 8);
	if(strlen(*block) < 8){
		for (int j = strlen(*block); j < 8; j++){
			(*block)[j] = '0';
		}
	}
	*ptr = hex_from_str(*block, err);
	//debug->all[debug->real_num] = *ptr;
	//debug->real_num++;
}


void res_block(int k, char** res, unsigned int ptr, char** p, int i){
	if (k == 0){
		strncpy(*res, str_from_hex(NULL, ptr, 8), 8);
		(*res)[8] = '\0';
	}
	else{
		strncat(*res, str_from_hex(NULL, ptr, 8), 8);
	}
}

unsigned int cbc_round(unsigned int* s_substitution, unsigned int ptr, unsigned int* key,
	 									unsigned int* iv, unsigned int iv1, int i, int crypt_mode, int k, Debug* debug){
	debug->all[debug->real_num] = ptr;
	debug->real_num++;
	if (crypt_mode == 1){
		ptr = encryption_cbc_round(s_substitution, ptr, key[i + 1], *iv, debug);
	}
	else{
		ptr = decryption_cbc_round(s_substitution, ptr, key[2 - i], *iv, debug);
	}
	return ptr;
}


unsigned int ecb_round(unsigned int* s_substitution, unsigned int ptr, unsigned int* key, int i, int crypt_mode, Debug* debug){
	debug->all[debug->real_num] = ptr;
	debug->real_num++;
	if (crypt_mode == 1){
		ptr = encryption_ecb_round(s_substitution, ptr, key[i + 1], debug);
	}
	else{
		ptr = decryption_ecb_round(s_substitution, ptr, key[2 - i], debug);
	}
	return ptr;
}


char* crypt (unsigned int* s_substitution, char* p, unsigned int* key, unsigned int iv, int blocks,
				int rounds, unsigned int iv1, unsigned int ptr, char* res, char* block, int err, char*first,
				int crypt_mode, char mode, Debug* debug){
	unsigned int iv0 = iv, pu = 0, iv_const = iv;
  for (int i = 0; i < blocks; i++){
		make_block (&block, p, &ptr, &err, debug);

		if (mode == 'o'){
			crypt_mode = 1;
			iv = ptr;
			ptr = iv0;
		}

		if (crypt_mode == 2){
			iv0 = ptr;
		}
		if (mode == 'c' && crypt_mode == 1){
			ptr = ptr ^ iv;
		}
		if (crypt_mode == 1){
			ptr = ptr ^ key[0];
		}
    for (int k = 0; k < rounds; k++){
			if (mode == 'e'){
				ptr = ecb_round (s_substitution, ptr, key, k, crypt_mode, debug);
			}
			else{
				ptr = cbc_round (s_substitution, ptr, key, &iv, iv1, k, crypt_mode, i, debug);
			}
			debug->all[debug->real_num] = ptr;
			debug->real_num++;
    }
		if (crypt_mode == 1){
			iv0 = ptr;

		}
		if(crypt_mode == 2){
			ptr = ptr ^ key[0];

		}
		if (mode == 'o'){
			iv0 = ptr;
			ptr = ptr ^ iv;
		}
		if (mode == 'c' && crypt_mode == 2){
			ptr = ptr ^ iv;
		}
		printf("%08x", ptr);
		debug->res[i] = ptr;
		block = str_from_hex(block, ptr, 8);
		res = strncat(res, block, 8);
		iv = iv0;
		p+=8;
  }
  res[8 * blocks] = '\0';
	printf("\n");
  return res;
}


void load_file (int argc, char** argv, char** p, int crypt_mode, char mode, unsigned int** s_substitution){
  if (crypt_mode == 1){
		load_straight(argv[argc - 1], p, s_substitution);
  }
  else if (crypt_mode == 2){
		load_back(argv[argc - 1], p, s_substitution);
	}
}


void back_subs (unsigned int ** s_substitution){
	for (int i = 0; i < 256; i++){
    (*s_substitution)[subs[i]] = i;
  }
}


void straight_subs(unsigned int ** s_substitution){
	for (int i = 0; i < 256; i++){
    (*s_substitution)[i] = subs[i];
  }
}


void load (int argc, char** argv, char** p, int crypt_mode, char mode, unsigned int** s_substitution){
  if (crypt_mode == 1){
		straight_subs(s_substitution);
		//*s_substitution = subs;
  }
  else if (crypt_mode == 2){
		back_subs(s_substitution);
	}
	FILE* fd;
  fd = fopen(argv[argc - 1], "r");
  *p = fgetstr(fd);
  fclose(fd);
}


char* init_n_cipher (int argc, char** argv, char* p, unsigned int* key, unsigned int iv, int crypt_mode, char mode, int debugger){
	unsigned int* s_substitution = (unsigned int*)malloc(256 * sizeof(unsigned int));
	if(mode == 'o'){
		crypt_mode = 1;
	}
	load(argc, argv, &p, crypt_mode, mode, &s_substitution);
	long int size = strlen(p);
	char* first = p;
	char* res = (char*)malloc((size/8 + 1) * 8 + 1);
	char* block = (char*)malloc(9);
	unsigned int ptr = 0, iv1 = iv;
  int rounds = 2, err = 0, blocks = size / 8;
	if(size % 8 != 0)
    blocks++;
  res[0] = '\0';
  block[8] = '\0';
	Debug* debug = init(blocks);
	debug->blocks_num = blocks;
	debug->skey = key[0];
	for (int i = 0; i < 2; i++){
		debug->key[i] = key[i+1];
	}
	debug->iv = iv;
	p = crypt (s_substitution, p, key, iv, blocks, rounds, iv1, ptr,
						res, block, err, first, crypt_mode, mode, debug);
	if (debugger == 1)
		print_debug(debug, crypt_mode, mode);
	free(s_substitution);
	free(block);
	free(first);
	delete_debug(debug);
  return p;
}


unsigned int* key_calculation (unsigned int k, unsigned int* key) {
  key[0] = k;
  while (k > 0){
    key[1] = key[1] << 1;
    key[1] |= k % 2;
    k = k / 2;
  }
  key[2] = key[0] ^ key[1];
  return key;
}

int D_Timing()
{
	unsigned int* key = (unsigned int*)calloc(3, sizeof(unsigned int));
	int n = 10, k= 0, cnt = 100000, i, m, z;
	clock_t first, last;
	unsigned int* s_substitution = (unsigned int*)malloc(256 * sizeof(unsigned int));
	key = key_calculation(k, key);
	straight_subs(&s_substitution);
	Debug* debug = init(1);
	unsigned int p, iv = 0;
	srand(time(NULL));
	first = clock();
	while (n-- > 0) {
		for (i = 0; i < cnt; ) {
			p = rand() * rand();
			p = p ^ key[0];
	    for (int k = 0; k < 2; k++)
					p = ecb_round (s_substitution, p, key, k, 1, debug);
			i++;
			debug->real_num = 0;
		}
		last = clock();
		printf("ecb test #%d, number of blocks = %d, time = %f ms\n", 10 - n, (10 -
			n) * cnt, (double)((last - first) * 1000/CLOCKS_PER_SEC));
	}
	printf("BLOCKS PER SECOND IN ECB  --- >   %f\n", (10 -
		n) * cnt * 1000 /(double)((last - first) * 1000/CLOCKS_PER_SEC));
	n = 10;
	first = clock();
	while (n-- > 0) {
		for (i = 0; i < cnt; ) {
			p = rand() * rand();
			p = p ^ iv;
			p = p ^ key[0];
	    for (int k = 0; k < 2; k++)
					p = ecb_round (s_substitution, p, key, k, 1, debug);
			iv = p;
			i++;
			debug->real_num = 0;
		}
		last = clock();
		printf("cbc test #%d, number of blocks = %d, time = %f ms\n", 10 - n, (10 -
			n) * cnt, (double)((last - first) * 1000/CLOCKS_PER_SEC));
	}
	printf("BLOCKS PER SECOND IN CBC  --- >   %f\n", (10 -
		n) * cnt * 1000 /(double)((last - first) * 1000/CLOCKS_PER_SEC));
	delete_debug(debug);
	free(key);
	free(s_substitution);
	return 1;
}


int main (int argc, char** argv) {
  unsigned int* key = (unsigned int*)calloc(3, sizeof(unsigned int));
  unsigned int k, iv;
  char * p, mode = '\0';
  int crypt_mode = 0, debugger = 0, timing = 0;
  int a = analyse_input(argc, argv, &k, &iv, &crypt_mode, &mode, &debugger, &timing);
	if(a == 0){
	  key = key_calculation(k, key);
	  p = init_n_cipher(argc, argv, p, key, iv, crypt_mode, mode, debugger);
	  //printf("%s\n", p);
		free(p);
	}
	else if (a == WRONG_VALUE){
		printf("Something wrong in command. If you need help enter -h flag.\n");
		printf("Correct form:\n");
		printf("./cipher -m ecb -e -k f0f0f0f0 input > output\n");
	}

	else {
		printf("Correct form for crypt text:\n");
		printf("./cipher -m ecb -e -k f0f0f0f0 input > output\n");
	}
	if(timing == 31)
		D_Timing();
	free(key);
	return 0;
}
