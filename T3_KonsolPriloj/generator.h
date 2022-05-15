#ifndef GENERATOR_H
#define GENERATOR_H


#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <time.h>


char* hash_modes[2];
char* cipher_modes[4];
char** modes[2];



#define WRONG_VALUE -1


char* concatenate_char(char* str1, char* str2);
unsigned char* concatenate(unsigned char* str1, unsigned char* str2, int len1, int len2);
char* construct_fname (int mode_hash, int mode_cipher, unsigned char* password);
unsigned char hex_from_str (char* arg, int* err);
int check_inarray (char* arg, char* array[], int count);
int analyse_input (int argc, char** argv,int* mode, unsigned char* pass);
int checker_symbol(unsigned char symb, int position);
char* fgetstr (FILE* fd);

#endif
