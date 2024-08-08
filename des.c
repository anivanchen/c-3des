#include "des.h"

#include "main.h"

/* HELPER FUNCTIONS */

void pbin(uint64_t input, int size) {
  char count = 0;
  for (int i = size - 1; i >= 0; i--) {
    if (count++ % 8 == 0 && i != size - 1) printf(" ");
    if ((input >> i) & 1)
      printf("1");
    else
      printf("0");
  }
  printf("\n");
}

/* KEY SCHEDULE GENERATION */

uint64_t pc_1_c(uint64_t key) {
  uint64_t output = 0;
  for (int i = 0; i < 28; i++) {
    output |= ((key >> (64 - PC_1_ARR[i])) & 1) << (27 - i);
  }

  return output;
}

uint64_t pc_1_d(uint64_t key) {
  uint64_t output = 0;
  for (int i = 0; i < 28; i++) {
    output |= ((key >> (64 - PC_1_ARR[i + 28])) & 1) << (27 - i);
  }
  return output;
}

uint64_t key_shift(uint64_t key, int round) {
  for (int i = 0; i < SHIFTS[round]; i++) {
    key = 0x0fffffff & (key << 1) | 1 & (key >> 27);
  }
  return key;
}

uint64_t pc_2(uint64_t c, uint64_t d) {
  uint64_t combined = c << 28 | d;
  uint64_t key = 0;

  for (int i = 0; i < 48; i++) {
    key |= ((combined >> (56 - PC_2_ARR[i])) & 1) << (47 - i);
  }

  return key;
}

uint64_t *generate_key_schedule(uint64_t key) {
  uint64_t c = pc_1_c(key);
  uint64_t d = pc_1_d(key);
  uint64_t *keys = malloc(16 * sizeof(uint64_t));

  for (int i = 0; i < 16; i++) {
    keys[i] = 0;
    c = key_shift(c, i);
    d = key_shift(d, i);
    keys[i] = pc_2(c, d);
  }

  return keys;
}

void print_key_schedule(uint64_t *keys) {
  for (int i = 0; i < 16; i++) {
    printf("Key %2.d: ", i + 1);
    pbin(keys[i], 48);
  }
}

/* DES ALGORITHM STEPS */

uint64_t initial_permutation(uint64_t input) {
  uint64_t output = 0;
  for (int i = 0; i < 64; i++) {
    output |= ((input >> (64 - IP_ARR[i])) & 1) << (63 - i);
  }
  return output;
}

uint64_t *split_l_r(uint64_t input) {
  uint64_t *output = malloc(2 * sizeof(uint64_t));
  output[0] = input >> 32;
  output[1] = input & 0xFFFFFFFF;
  return output;
}

uint64_t e(uint64_t chunk) {
  uint64_t output = 0;
  for (int i = 0; i < 48; i++) {
    output |= ((chunk >> (32 - E_ARR[i])) & 1) << (47 - i);
  }
  return output;
}

uint64_t input_key_xor(uint64_t input, uint64_t key) {
  uint64_t output = 0;
  for (int i = 0; i < 48; i++) {
    output |= (((input >> (47 - i)) & 1) ^ ((key >> (47 - i)) & 1)) << (47 - i);
  }
  return output;
}

uint64_t s_box_substitution(uint64_t xored_chunk) {
  uint8_t small_chunks[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint64_t output = 0;

  for (int i = 0; i < 8; i++) {
    small_chunks[i] = xored_chunk >> (48 - 6 * (i + 1)) & 63;
  }

  for (int i = 0; i < 8; i++) {
    int row = (small_chunks[i] >> 5 << 1) | (small_chunks[i] & 1);
    int col = (small_chunks[i] & ~(1 << 5) & ~1) >> 1;
    output = output << 4;
    output |= S_PRIM_ARR[i][row * 16 + col];
  }

  return output;
}

uint64_t p(uint64_t chunk) {
  uint64_t output = 0;
  for (int i = 0; i < 32; i++) {
    output |= ((chunk >> (32 - P_ARR[i])) & 1) << (31 - i);
  }
  return output;
}

uint64_t f(uint64_t chunk, uint64_t key) {
  return p(s_box_substitution(input_key_xor(e(chunk), key)));
}

uint64_t l_r_xor(uint64_t l, uint64_t r) { return l ^ r; }

uint64_t final_permutation(uint64_t input) {
  uint64_t output = 0;
  for (int i = 0; i < 64; i++) {
    output |= ((input >> (64 - IPI_ARR[i])) & 1) << (63 - i);
  }
  return output;
}

/* DES ENCRYPTION & DECRYPTION */

uint64_t des_encrypt(uint64_t data, uint64_t key_64) {
  uint64_t *split = split_l_r(initial_permutation(data));
  uint64_t *key_schedule = generate_key_schedule(key_64);

  uint64_t l = split[0];
  uint64_t r = split[1];

  for (int i = 0; i < 16; i++) {
    uint64_t temp = r;
    r = l_r_xor(l, f(r, key_schedule[i]));
    l = temp;
  }

  return final_permutation(r << 32 | l);
}

uint64_t des_decrypt(uint64_t data, uint64_t key_64) {
  uint64_t *split = split_l_r(initial_permutation(data));
  uint64_t *key_schedule = generate_key_schedule(key_64);

  uint64_t l = split[0];
  uint64_t r = split[1];

  for (int i = 0; i < 16; i++) {
    uint64_t temp = r;
    r = l_r_xor(l, f(r, key_schedule[15 - i]));
    l = temp;
  }

  return final_permutation(r << 32 | l);
}

int des_encrypt_file(char *input_filename, char *output_filename,
                     uint64_t key_64) {
  FILE *input_file = fopen(input_filename, "r");
  FILE *output_file = fopen(output_filename, "w");

  if (input_file == NULL || output_file == NULL) {
    return -1;
  }

  uint64_t *key_schedule = generate_key_schedule(key_64);
  uint64_t buffer = 0;
  uint64_t encrypted = 0;

  fseek(input_file, 0L, SEEK_END);
  int remain = (ftell(input_file) % 8);
  fseek(input_file, 0L, SEEK_SET);

  while (fread(&buffer, sizeof(uint64_t), 1, input_file) == 1) {
    encrypted = des_encrypt(buffer, key_64);
    fwrite(&encrypted, sizeof(uint64_t), 1, output_file);
  }

  uint64_t mask;
  int remain_bytes = 8 - remain;
  for (mask = 0x00; remain_bytes; remain_bytes--) {
    mask = mask << 8 | 0xFF;
  }

  fread(&buffer, sizeof(uint64_t), 1, input_file);
  buffer = mask | buffer << (8 * (8 - remain));
  encrypted = des_encrypt(buffer, key_64);
  fwrite(&encrypted, sizeof(uint64_t), 1, output_file);

  fclose(input_file);
  fclose(output_file);

  return 0;
}

int des_decrypt_file(char *input_filename, char *output_filename,
                     uint64_t key_64) {
  FILE *input_file = fopen(input_filename, "r");
  FILE *output_file = fopen(output_filename, "w");

  if (input_file == NULL || output_file == NULL) {
    return -1;
  }

  uint64_t *key_schedule = generate_key_schedule(key_64);
  uint64_t buffer = 0;
  uint64_t decrypted = 0;

  fseek(input_file, 0L, SEEK_END);
  int size = ftell(input_file) / 8;
  fseek(input_file, 0L, SEEK_SET);

  int counter = 0;
  while (fread(&buffer, sizeof(uint64_t), 1, input_file) == 1) {
    decrypted = des_decrypt(buffer, key_64);
    int count = 0;
    if (counter == size - 1) {
      while ((decrypted & 0xFF) == 255) {
        decrypted = decrypted >> 8;
        count++;
      }
    }
    fwrite(&decrypted, 8 - count, 1, output_file);
    counter++;
  }

  fclose(input_file);
  fclose(output_file);

  return 0;
}

int triple_des_encrypt_file(char *input_filename, char *output_filename,
                            uint64_t key1, uint64_t key2, uint64_t key3) {
  
  if (opendir(".tmp") == NULL) mkdir(".tmp", 0700);

  des_encrypt_file(input_filename, ".tmp/key1.enc", key1);
  des_decrypt_file(".tmp/key1.enc", ".tmp/key2.dec", key2);
  des_encrypt_file(".tmp/key2.dec", output_filename, key3);
  
  remove(".tmp/key1.enc");
  remove(".tmp/key2.dec");
  rmdir(".tmp");
  return 0;
}

int triple_des_decrypt_file(char *input_filename, char *output_filename,
                            uint64_t key1, uint64_t key2, uint64_t key3) {
  
  if (opendir(".tmp") == NULL) mkdir(".tmp", 0700);

  des_decrypt_file(input_filename, ".tmp/key3.dec", key3);
  des_encrypt_file(".tmp/key3.dec", ".tmp/key2.enc", key2);
  des_decrypt_file(".tmp/key2.enc", output_filename, key1);
  
  remove(".tmp/key3.dec");
  remove(".tmp/key2.enc");
  rmdir(".tmp");
  return 0;
}
