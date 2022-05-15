#include "generator.h"


char* hash_modes[] = {"md5", "sha1"};
char* cipher_modes[] = {"3des", "aes128", "aes192", "aes256"};
char** modes[] = {hash_modes, cipher_modes};


unsigned char* concatenate(unsigned char* str1, unsigned char* str2, int len1, int len2){
  str1 = (unsigned char*)realloc(str1, len1 + len2 + 1);
  //int len = strlen((char*)str2);
  for (int i = 0; i < len2; i++) {
    
    str1[len1 + i] = str2[i];
  }
  //memcpy(str1 + strlen((char*)str1), str2, strlen((char*)str2));
  str1[len2 + len1] = '\0';
  return str1;
}


char* concatenate_char(char* str1, char* str2){
  str1 = (char*)realloc(str1, strlen(str2) + strlen(str1) + 1);
  memcpy(str1 + strlen((char*)str1), str2, strlen((char*)str2));
  str1[strlen(str1) + strlen(str2)] = '\0';
  return str1;
}


char* construct_fname (int mode_hash, int mode_cipher, unsigned char* password) {
  char* file_name = (char*)calloc(15 + strlen(hash_modes[mode_hash]) + strlen(cipher_modes[mode_cipher]), sizeof(char));
  strcat(file_name, hash_modes[mode_hash]);
  strcat(file_name, "_");
  strcat(file_name, cipher_modes[mode_cipher]);
  strcat(file_name, "_");
  unsigned char u = 0;
  char* hex_symbol = (char*)malloc(2);
  hex_symbol[1] = '\0';
  for (int i = 0; i < 8; i++) {
    if (i % 2 == 0) {
      u = password[i/2] / (1 << 4);
    }
    else {
      u = password[i/2] % (1 << 4);
    }
    if (u > 9) {
        hex_symbol[0] = u + 'a' - 10;
    }
    else {
      hex_symbol[0] = u + '0';
    }
    strcat(file_name, hex_symbol);
  }
  strcat(file_name, ".enc");
  return file_name;
}



char* construct_fname_old (int mode_hash, int mode_cipher, unsigned char* password){
  char* separator = "_";
  char* file_name = (char*)calloc(1, sizeof(char));
  char* hmode = (char*)malloc(strlen(hash_modes[mode_hash]) + 1);

  hmode[strlen(hash_modes[mode_hash])] = '\0';
  strcpy(hmode, hash_modes[mode_hash]);
  file_name = concatenate_char(file_name, hmode);
  file_name = concatenate_char(file_name, separator);
  char* cmode = (char*)malloc(strlen(cipher_modes[mode_cipher]) + 1);
  cmode[strlen(cipher_modes[mode_cipher])] = '\0';
  strcpy(cmode, cipher_modes[mode_cipher]);
  file_name = concatenate_char(file_name, cmode);
  file_name = concatenate_char(file_name, separator);
  char* hex_symbol = (char*)malloc(2);
  unsigned char u = 0;
  hex_symbol[1] = '\0';
  for (int i = 0; i < 8; i++) {
    if (i % 2 == 0) {
      u = password[i/2] / (1 << 4);
    }
    else {
      u = password[i/2] % (1 << 4);
    }
    if (u > 9) {
        hex_symbol[0] = u + 'a' - 10;
    }
    else {
      hex_symbol[0] = u + '0';
    }
    file_name = concatenate_char (file_name, hex_symbol);
  }
  char* enc = ".enc";
  file_name = concatenate_char (file_name, enc);
  file_name[strlen(file_name) - 3] = '\0';
  free(hmode);
  return file_name;
}


unsigned char hex_from_str (char* arg, int* err) {
  unsigned char res = 0;
  for (int i = 0; i < strlen(arg); i++){
    res *= 16;
    unsigned long long a = 0;
    if (arg[i] >= '0' && arg[i] <= '9'){
      a = arg[i] - '0';
    }
    else if (arg[i] >= 'a' && arg[i] <= 'f'){
      a = arg[i] - 'a' + 10;
    }
    else{
      printf("%02x --- wrong value\n", arg[i]);
      *err = WRONG_VALUE;
      return res;
    }
    res += a;
  }
  return res;
}


int check_inarray (char* arg, char* array[], int count) {
  int res = WRONG_VALUE;
  for (int i = 0; i < count; i++) {
    if (strcmp(arg, array[i]) == 0) {
      res = i;
    }
  }
  return res;
}


int analyse_input (int argc, char** argv,int* mode, unsigned char* pass) {
 if (argc != 4 || strlen(argv[1]) < 8){
   return WRONG_VALUE;
 }
 int err = 0;
 char* str = (char*)malloc(2);
 for (int i = 0; i < 4; i++) {
   str[0] = argv[1][2 * i];
   str[1] = argv[1][2 * i + 1];
   pass[i] = hex_from_str(str, &err);
   if(err == WRONG_VALUE){
     return WRONG_VALUE;
   }
 }

 char* a = argv[2];
 for(int j = 0; j < 2; j++){
   err = check_inarray(a, modes[j], (j + 1) * 2);
   if(err == WRONG_VALUE){
     printf("here j = %d\n", j);
     return WRONG_VALUE;
   }
   mode[j] = err;
   a = argv[2 + j + 1];
 }
 return 0;
}
