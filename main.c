#include "des.h"
#include "sha.h"

void assert(uint64_t input, uint64_t expected, char *message) {
  if (input != expected) {
    printf("\033[1;31mFailed\033[0m: \033[0;34m%s\033[0m\n\n", message);
    printf("\033[1;36mExpected\033[0m:\033[0;34m");
    pbin(expected, 64);
    printf("\033[0m\033[1;33mReceived\033[0m:\033[0;34m");
    pbin(input, 64);
    printf("\033[0m");
    exit(1);
  } else {
    printf("\033[1;32mPassed\033[0m: \033[0;34m%s\033[0m\n", message);
  }
}

void run_tests() {
  uint64_t m = 81985529216486895ULL;
  uint64_t k = 1383827165325090801ULL;

  // Test initial_permutation
  uint64_t ip = initial_permutation(m);
  assert(ip, 14699974583363760298ULL, "initial_permutation");

  // Test split_l_r
  uint64_t *split = split_l_r(ip);
  assert(split[0], 3422604543, "split_l");
  assert(split[1], 4037734570, "split_r");

  // Test pc_1_c
  uint64_t pc1c = pc_1_c(k);
  assert(pc1c, 252496559, "pc_1_c");

  // Test pc_1_d
  uint64_t pc1d = pc_1_d(k);
  assert(pc1d, 89548687, "pc_1_d");

  // Test key_shift
  uint64_t ksc = key_shift(pc1c, 1);
  assert(ksc, 236557663, "key_shift 1c");
  uint64_t ksd = key_shift(pc1d, 1);
  assert(ksd, 179097374, "key_shift 1d");

  // Test pc_2
  uint64_t pc2 = pc_2(ksc, ksd);
  assert(pc2, 29699430183026, "pc_2");

  // Test generate_key_schedule
  uint64_t *keys = generate_key_schedule(k);
  assert(keys[0], 29699430183026, "generate_key_schedule 1");
  assert(keys[1], 133791886330341, "generate_key_schedule 2");
  assert(keys[2], 94543139753881, "generate_key_schedule 3");
  assert(keys[3], 126090959598877, "generate_key_schedule 4");
  assert(keys[4], 137353186988968, "generate_key_schedule 5");
  assert(keys[5], 109561366215471, "generate_key_schedule 6");
  assert(keys[6], 260054766196924, "generate_key_schedule 7");
  assert(keys[7], 272173063289851, "generate_key_schedule 8");
  assert(keys[8], 247235160696705, "generate_key_schedule 9");
  assert(keys[9], 195658438559311, "generate_key_schedule 10");
  assert(keys[10], 36695460205446, "generate_key_schedule 11");
  assert(keys[11], 129132311898089, "generate_key_schedule 12");
  assert(keys[12], 166875887221313, "generate_key_schedule 13");
  assert(keys[13], 104744453596986, "generate_key_schedule 14");
  assert(keys[14], 210631860764426, "generate_key_schedule 15");
  assert(keys[15], 223465186400245, "generate_key_schedule 16");

  // Test output of rounds 1-16
  uint64_t l = split[0];
  uint64_t r = split[1];
  for (int i = 0; i < 16; i++) {
    uint64_t temp = r;
    r = l_r_xor(l, f(r, keys[i]));
    l = temp;
  }
  assert(l, 1128411700, "round(16) l");
  assert(r, 172808597, "round(16) r");
  assert(r << 32 | l, 742207273711055412ULL, "round(16) rl");

  // Test final_permutation
  uint64_t output = final_permutation(r << 32 | l);
  assert(output, 9648983453391827973ULL, "final_permutation");

  // Test des_encrypt
  uint64_t encrypted = des_encrypt(m, k);
  assert(encrypted, 9648983453391827973ULL, "des_encrypt");

  // Test des_decrypt
  uint64_t decrypted = des_decrypt(encrypted, k);
  assert(decrypted, m, "des_decrypt");
}

int main(int argc, char *argv[]) {

  if (argc == 2 && strcmp(argv[1], "test") == 0) {
    run_tests();
  } else if (argc == 3 && strcmp(argv[1], "sha") == 0) {
    sha256_file(argv[2], "sha_output.txt");
  }
  else {

    if (argc < 5) {
        printf("Usage: make [encrypt/decrypt] [input_file] [output_file] [password_file] [triple_des]\n");
        return 1;
    }

    uint64_t *hash = malloc(32);
    hash = sha256(argv[4]);

    if (argc > 3) {
        if (strcmp(argv[1], "encrypt") == 0) {
        if (argc > 4 && strcmp(argv[5], "true") == 0)
            triple_des_encrypt_file(argv[2], argv[3], hash[0], hash[1], hash[2]);
        else
            des_encrypt_file(argv[2], argv[3], hash[0]);
        } else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc > 4 && strcmp(argv[5], "true") == 0)
            triple_des_decrypt_file(argv[2], argv[3], hash[0], hash[1], hash[2]);
        else
            des_decrypt_file(argv[2], argv[3], hash[0]);
        }
    }
  }
}
