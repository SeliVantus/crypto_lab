#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include "protocol_funcs.h"


int main(int argc, char** argv){
  int* mode = (int*)malloc(2 * sizeof(int));
  unsigned char* password = (unsigned char*)malloc(4 * sizeof(unsigned char));
  int a = analyse_input (argc, argv, mode, password);
  if(a == WRONG_VALUE) {
    printf("WRONG INPUT\n");
    return 0;
  }
  generator(mode[0], mode[1], password);
  return 0;
}
