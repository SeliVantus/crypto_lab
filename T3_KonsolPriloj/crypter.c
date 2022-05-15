#include "protocol_funcs.h"



int main(int argc, char** argv) {
  unsigned char *pass = NULL, *nonce = NULL, *iv = NULL;
  char* input_filename = NULL, *output_filename = NULL;
  int mode_hash = 1, mode_cipher = 1, crypt_mode = -1;
  int a = analyse_input_crypt(argc, argv, &iv, &nonce, &mode_cipher,
          &mode_hash, &crypt_mode, &pass, &input_filename, &output_filename);

  if (a == WRONG_VALUE) {
    printf("WRONG INPUT\n");
    return 0;
  }
  else if (a == 1){
    return 0;
  }
  else  if (crypt_mode == DECRYPT){
    int err = file_checker(input_filename);
    if (err == WRONG_VALUE) {
      printf("Invalid file!\n");
    }
    else{
      printf("Valid file!\n");
      unsigned char* text = decrypt(input_filename, pass, output_filename);
      return 0;
    }
  }
  else {
    cipher(mode_hash, mode_cipher,  pass, iv, nonce, output_filename, input_filename);
  }
  return 0;
}
