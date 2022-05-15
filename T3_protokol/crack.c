#include "protocol_funcs.h"





int main(int argc, char** argv) {
  int verbose = 1, parallel = 0;
  if (argc < 2) {
    printf("Wong input. No entered file for cracking\n");
    return 0;
  }
  
  int c = analyse_input_cracker(argc, argv, &verbose, &parallel);
  if (c == 5) {
    return 0;
  }
  int err = file_checker(argv[argc - 1]);
  if (err == WRONG_VALUE) {
    printf("Invalid file!\n");
  }
  else{
    printf("Valid file!\n");
    if (parallel == 0) {
      int a = cracker(argv[argc - 1], verbose);
    }
    else{
      int a = cracker_forked(argv[argc - 1], verbose);

    }
    return 0;
  }
}
