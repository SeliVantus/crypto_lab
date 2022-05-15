#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <time.h>


#define WRONG_VALUE -1
#define SUCCESS 0
#define NO_ARGS -2


int read_key_file(char***regs, int** sizes, char* file_name);
unsigned long long hex_from_str (char* arg, int* err);
void init_registers(char*** regs, int** sizes);
void clean_memory(char*** regs, int** sizes);
void cipher (char**regs, int* sizes, char* text1);
int analyse_input (int argc, char** argv, char** key);
char* read_text_file(char* file_name);
void register_transform (char*** regs, int* sizes, unsigned int** reg_ex);
unsigned int new_value (char* reg, int size);
void shift_register (char** reg, int size, unsigned int value);
unsigned int func (unsigned int a, unsigned int b, unsigned int c);
char* fgetstr (FILE* fd);



int main(int argc, char** argv) {
  char **regs;
  int *sizes, t;
  char* file_name = "\0", *text;
  init_registers(&regs, & sizes);//works
  t = analyse_input (argc, argv, &file_name);//works
  if (t == WRONG_VALUE)
    printf("Wrong input. Please, try again.\n");
  else if (t == NO_ARGS)
    printf("\n");
  else{
    t = read_key_file(&regs, &sizes, file_name);//works
    if (t == WRONG_VALUE)
      printf("Wrong input. Please, try again.\n");
    else{
      text = read_text_file(argv[argc - 1]);//works
      cipher(regs, sizes, text);//works
    }
  }
  clean_memory(&regs, &sizes);
  return 0;
}


void cipher (char**regs, int* sizes, char* text1) {
  char* text = text1;
  unsigned int* reg_ex = (unsigned int*)malloc(3 * sizeof(unsigned int));
  unsigned int x = 0, t = 0;
  int err = 0, i = 0;
  char* s = (char*)malloc(3);
  s[2] = '\0';
  while (*text != '\0') {
    s[0] = *text;
    s[1] = *(text + 1);
    t = hex_from_str(s, &err);
    if (err == WRONG_VALUE) {
      printf("Wrong text format. Please, check it.\n");
      free(reg_ex);
      return;
    }
    register_transform(&regs, sizes, &reg_ex);
    //for (int i = 0; i < 7; i++){
      //printf("%02x", (*regs)[i]);
    //}
    //printf("\n");
    x = func(*reg_ex, *(reg_ex + 1), *(reg_ex + 2));
    i++;
    printf("%02x   %02x   %02x\n", *reg_ex, *(reg_ex + 1), *(reg_ex + 2));
    printf("%02x\n", x);
    //x = x ^ ((unsigned int)*text);
    x = x ^ t;
    //printf("%02x", x);
    //text++;
    text+=2;
  }
  printf("\n");
  free(reg_ex);
}


void register_transform (char*** regs, int* sizes, unsigned int** reg_ex) {
  char ** reg = *regs;
  unsigned int *ex = *reg_ex, value = 0;
  int *s = sizes;
  for (int i = 0; i < 3; i++){
    *ex = (unsigned int)**reg;
    value = new_value(*reg, *s);
    shift_register(reg, *s, value);
    reg++;
    s++;
    ex++;
  }
}


unsigned int new_value (char* reg, int size) {
  unsigned int a, b, c, p = 0;
  a = (unsigned int)(*(reg + (size - 7)));
  b = (unsigned int)(*(reg + (size - 5)));
  c = (unsigned int)(*(reg + (size - 3)));
  p = a ^ b ^ c ^ 0x1;
  return p;
}


void shift_register (char** reg, int size, unsigned int value) {
  char* r = * reg;
  for (int i = 0; i < size - 1; i++){
    *r = *(r + 1);
    r++;
  }
  *r = (char)value;
}


unsigned int func (unsigned int a, unsigned int b, unsigned int c) {
  unsigned int p = 0, mod = (1 << 8);
  p = (((a * b * c) % mod) + ((a * b) % mod) + ((a * c) % mod) + 1) % mod;
  return p;
}


char* read_text_file(char* file_name) {
  FILE* fd;
  fd = fopen(file_name, "r");
  char* str = fgetstr(fd);
  fclose(fd);
  return str;
}


int read_key_file (char***regs, int** sizes, char* file_name) {
  FILE* fd;
  int err = 0, *s = *sizes;
  char ** r = *regs, *m = **regs;
  unsigned int p = 0;
  char* str = (char*)malloc(3);
  str[2] = '\0';
  fd = fopen(file_name, "r");
  for (int i = 0; i < 3; i++){
    m = *r;
    for (int j = 0; j < s[i]; j++){
      fgets(str, 3, fd);
      if (strlen(str) < 2){
        fclose(fd);
        printf("WRONG_VALUE\n");
        return WRONG_VALUE;
      }
      p = hex_from_str(str, &err);
      if (err == WRONG_VALUE){
        fclose(fd);
        return WRONG_VALUE;
      }
      *m = (char)p;
      m++;
      str[0] = '\0';
    }
    r++;
  }
  fclose(fd);
  free(str);
  return SUCCESS;
}


unsigned long long hex_from_str (char* arg, int* err) {
  unsigned long long res = 0;
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
      printf("%c --- wrong value\n", arg[i]);
      *err = WRONG_VALUE;
      return res;
    }
    res += a;
  }
  return res;
}

//working function
void init_registers (char*** regs, int** sizes) {
  *sizes = (int*)malloc(3 * sizeof(int));
  *regs = (char**)malloc(3 * sizeof(char*));
  int* p = *sizes;
  char** r = *regs, *m = *r;
  for (int i = 0; i < 3; i++){
    m = *r;
    *p = 7 + 2 * i;
    *r = (char*)malloc(p[i]+1);
    m+= *p;
    *((*r) + (*p)) = '\0';
    p++;
    r++;
  }
}


void clean_memory (char*** regs, int** sizes) {
  for (int i = 0; i < 3; i++){
    free ((*regs)[i]);
  }
  free(*regs);
  free(*sizes);
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


int analyse_input (int argc, char** argv, char** key) {
  const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"key", required_argument, NULL, 'k'},
    {NULL, 0, NULL, 0}
  };
	int key_here = 0;
  const char* short_options = "hvk:";
  int wrong = 1;
  while (optind < argc - 1 || optind < 2){
    int cc = getopt_long(argc, argv, short_options, long_options, NULL);
    char c = cc;
    switch (c) {
      case 'h': {
        printf("-v, --version for software version\n");
        printf("-k, --key=[value] for key init\n");
        printf("Example:\n./cipher -k key_file text_file\n");
				wrong = 0;
				continue;
      }
      case 'v':{
        printf("Software version 1.0\n");
				wrong = 0;
				continue;
      }
      case 'k':{
				key_here = 1;
        *key = optarg;
        continue;
			}
      case -1:{
				argc--;
				optind++;
				break;
      }
    }
  }
	if (key_here == 0){
		if(wrong == 1)
			return WRONG_VALUE;
		else
			return NO_ARGS;
    }
  return 0;
}
