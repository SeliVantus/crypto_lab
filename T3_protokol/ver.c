#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "protocol_funcs.h"


#define WRONG_VALUE -1


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
			strncat(ptr,buf, k);
		}
	} while (n > 0);
  ptr[strlen(ptr)] = '\0';
	return ptr;
}


int file_checker_new(char* file_name){
  FILE* fd;
  int size = 0, err;
  fd = fopen(file_name, "r");
  if (fd == NULL){
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
      return WRONG_VALUE;
    }
  }
  return 0;
}


int file_checker_old(char* file_name){
  FILE* fd;
  fd = fopen(file_name, "r");

  char* str = fgetstr(fd);
  int len = strlen(str);
  int err = 0;
  unsigned char q = 0;
  char* s = (char*)malloc(3);
  s[2] = '\0';
  printf("%s\n", file_name);
  for (int i = 0; i < len; i+=2){
    s[0] = *str;
    s[1] = *(str + 1);
    q = hex_from_str(s, &err);
    if (err == WRONG_VALUE){
      printf("THIS IS STR \"%d\"\"%d\"\n", s[0], s[1]);
      printf("%02x\n", q);
      break;
    }
    err = checker_symbol(q, i / 2);
    if (err == WRONG_VALUE){
      printf("%s\n", s);
      printf("%c\n", q);
      break;
    }
    str+=2;
  }
  fclose(fd);
  return err;
}


int main(int argc, char** argv){
  int a = file_checker_new(argv[argc-1]);
  if (a == WRONG_VALUE) {
    printf("False\n");
  }
  else {
    printf("True\n");
  }
  return 0;
}
