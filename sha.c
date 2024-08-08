/*
 * Implementation of SHA-256 in this file was co-written 
 * by Edmund Chin, Clemens Li, and Tracey Lin.
 *
 * All Rights Reserved (c) 2024 Edmund Chin, Clemens Li, Tracey Lin
 */

#include "sha.h"

#include "des.h"
#include "main.h"

int err(int line) {
  printf("line: %d\n", line);
  printf("errno %d\n", errno);
  printf("%s\n", strerror(errno));
  exit(1);
}

void uint32_to_hex(uint32_t num, char *hex_str) {
  // Format the uint32_t number into a hexadecimal string
  sprintf(hex_str, "%08X", num);
}

uint32_t rotate(uint32_t input, int shift) {
  return input >> shift | input << (32 - shift);
}

uint32_t funct0(uint32_t n0) {
  uint32_t a = rotate(n0, 7);
  uint32_t b = rotate(n0, 18);
  uint32_t c = n0 >> 3;
  return ((a ^ b) ^ c);
}

uint32_t funct1(uint32_t n0) {
  uint32_t a = rotate(n0, 17);
  uint32_t b = rotate(n0, 19);
  uint32_t c = n0 >> 10;
  return ((a ^ b) ^ c);
}

uint32_t sum0(uint32_t n0) {
  return (rotate(n0, 2) ^ rotate(n0, 13) ^ rotate(n0, 22));
}

uint32_t sum1(uint32_t n0) {
  return (rotate(n0, 6) ^ rotate(n0, 11) ^ rotate(n0, 25));
}

uint32_t majority(uint32_t n0, uint32_t n1, uint32_t n2) {
  return ((n0 & n1) ^ (n0 & n2) ^ (n1 & n2));
}

uint32_t choice(uint32_t n0, uint32_t n1, uint32_t n2) {
  return ((n0 & n1) ^ ((~n0) & n2));
}

uint32_t *pad(char *input, int chunkNum) {
  int size = chunkNum * 16;
  uint32_t *output = (uint32_t *)malloc(size * 32);
  for (int i = 0; i < size; i++) {
    output[i] = 0b0;
  }
  bool onepadded = false;
  int blockNum = 0;
  for (int i = 0; i < strlen(input) + (4 - (strlen(input) % 4)); i++) {
    if (i / 4 > blockNum) {
      blockNum++;
    }
    output[blockNum] = output[blockNum] << 8;
    if (i >= strlen(input)) {
      if (!onepadded) {
        onepadded = !onepadded;
        output[blockNum] |= 128;
      } else {
        output[blockNum] |= 0b0;
      }
    } else {
      output[blockNum] |= input[i];
    }
  }
  blockNum = size - 2;
  uint64_t plainLength = strlen(input) * 8;
  output[blockNum] = (plainLength & 0xFFFFFFFF00000000) >> 32;
  output[blockNum + 1] = plainLength & 0x00000000FFFFFFFF;
  uint32_t *ptr = output;
  return ptr;
}

uint64_t *sha256(char *input_filename) {
  FILE *file = fopen(input_filename, "r");

  fseek(file, 0, SEEK_END);
  uint64_t fileLength = ftell(file);
  int num_chunks = (int)(trunc(fileLength / 64) + 1);
  fseek(file, 0, SEEK_SET);

  //   printf("size: %ld\n", fileLength);
  //   printf("num_chunks: %d\n", num_chunks);

  uint32_t *hashes = malloc(32);
  char *array = malloc(fileLength * sizeof(char));
  char buffer = 0;
  int counter = 0;

  while (fread(&buffer, sizeof(char), 1, file) == 1) {
    array[counter++] = buffer;
  }
  uint32_t temp1 = 0;
  uint32_t temp2 = 0;
  /* PREPROCESSING */

  uint32_t H[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++) H[i] = HASH_ARR[i];

  uint32_t a, b, c, d, e, f, g, h;

  uint32_t t1 = 0;
  uint32_t t2 = 0;

  uint32_t *paddedData;
  paddedData = pad(array, num_chunks);
  /* HASH COMPUTATION */

  //   for (int i = 0; i < 32; i++) {
  //     if (i == 16) {
  //       printf("\n");
  //       printf("\n");
  //     }
  //     pbin(*(paddedData + i), 32);
  //   }

  uint32_t *chunk = malloc(256);
  //   printf("\n");
  for (int i = 0; i < num_chunks; i++) {
    int curr = i * 16;
    for (int j = 0; j < 16; j++) {  // pull 16 lines of 4 bytes
      chunk[j] = paddedData[curr + j];
    }
    for (int k = 0; k < 48; k++) {  // calculate the rest of the array
      chunk[k + 16] = (chunk[k] + funct0(chunk[k + 1]) + chunk[k + 9] +
                       funct1(chunk[k + 14]));
    }

    if (i == 0) {
      a = HASH_ARR[0];
      b = HASH_ARR[1];
      c = HASH_ARR[2];
      d = HASH_ARR[3];
      e = HASH_ARR[4];
      f = HASH_ARR[5];
      g = HASH_ARR[6];
      h = HASH_ARR[7];
      hashes[0] = HASH_ARR[0];
      hashes[1] = HASH_ARR[1];
      hashes[2] = HASH_ARR[2];
      hashes[3] = HASH_ARR[3];
      hashes[4] = HASH_ARR[4];
      hashes[5] = HASH_ARR[5];
      hashes[6] = HASH_ARR[6];
      hashes[7] = HASH_ARR[7];
    } else {
      a = hashes[0];
      b = hashes[1];
      c = hashes[2];
      d = hashes[3];
      e = hashes[4];
      f = hashes[5];
      g = hashes[6];
      h = hashes[7];
    }
    for (int j = 0; j < 64; j++) {
      temp1 = h + sum1(e) + choice(e, f, g) + K_ARR[j] + chunk[j];
      temp2 = sum0(a) + majority(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    hashes[0] += a;
    hashes[1] += b;
    hashes[2] += c;
    hashes[3] += d;
    hashes[4] += e;
    hashes[5] += f;
    hashes[6] += g;
    hashes[7] += h;
  }

  uint64_t *result = malloc(4 * sizeof(uint64_t));

  for (int i = 0; i < 4; i++) {
    result[i] = (uint64_t)hashes[i * 2] << 32 | hashes[i * 2 + 1];
  }

  return result;
}

void sha256_file(char *input_filename, char *output_filename) {
  /* READ FILE INTO ARRAY */

  // Get num_chunks = (length of the file / 512) + 1
  // Create an array of num_chunks long
  // Read file char by char into buffer
  // For each char, write to the count / 4th index of the array
  // Shift the array[count/4] by 8, then OR the buffer into the array[count/4]

  FILE *file = fopen(input_filename, "r");

  fseek(file, 0, SEEK_END);
  uint64_t fileLength = ftell(file);
  int num_chunks = (int)(trunc(fileLength / 64) + 1);
  fseek(file, 0, SEEK_SET);

//   printf("size: %ld\n", fileLength);
//   printf("num_chunks: %d\n", num_chunks);

  uint32_t *hashes = malloc(32);
  char *array = malloc(fileLength * sizeof(char));
  char buffer = 0;
  int counter = 0;

  while (fread(&buffer, sizeof(char), 1, file) == 1) {
    array[counter++] = buffer;
  }
  uint32_t temp1 = 0;
  uint32_t temp2 = 0;
  /* PREPROCESSING */

  uint32_t H[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++) H[i] = HASH_ARR[i];

  uint32_t a, b, c, d, e, f, g, h;

  uint32_t t1 = 0;
  uint32_t t2 = 0;

  // TODO: Pad the array
  uint32_t *paddedData;
  paddedData = pad(array, num_chunks);
  /* HASH COMPUTATION */

//   for (int i = 0; i < 32; i++) {
//     if (i == 16) {
//       printf("\n");
//       printf("\n");
//     }
//     pbin(*(paddedData + i), 32);
//   }

  uint32_t *chunk = malloc(256);
  printf("\n");
  for (int i = 0; i < num_chunks; i++) {
    int curr = i * 16;
    for (int j = 0; j < 16; j++) {  // pull 16 lines of 4 bytes
      chunk[j] = paddedData[curr + j];
    }
    for (int k = 0; k < 48; k++) {  // calculate the rest of the array
      chunk[k + 16] = (chunk[k] + funct0(chunk[k + 1]) + chunk[k + 9] +
                       funct1(chunk[k + 14]));
    }

    if (i == 0) {
      a = HASH_ARR[0];
      b = HASH_ARR[1];
      c = HASH_ARR[2];
      d = HASH_ARR[3];
      e = HASH_ARR[4];
      f = HASH_ARR[5];
      g = HASH_ARR[6];
      h = HASH_ARR[7];
      hashes[0] = HASH_ARR[0];
      hashes[1] = HASH_ARR[1];
      hashes[2] = HASH_ARR[2];
      hashes[3] = HASH_ARR[3];
      hashes[4] = HASH_ARR[4];
      hashes[5] = HASH_ARR[5];
      hashes[6] = HASH_ARR[6];
      hashes[7] = HASH_ARR[7];
    } else {
      a = hashes[0];
      b = hashes[1];
      c = hashes[2];
      d = hashes[3];
      e = hashes[4];
      f = hashes[5];
      g = hashes[6];
      h = hashes[7];
    }
    for (int j = 0; j < 64; j++) {
      temp1 = h + sum1(e) + choice(e, f, g) + K_ARR[j] + chunk[j];
      temp2 = sum0(a) + majority(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    hashes[0] += a;
    hashes[1] += b;
    hashes[2] += c;
    hashes[3] += d;
    hashes[4] += e;
    hashes[5] += f;
    hashes[6] += g;
    hashes[7] += h;
  }
  char *result[8];
  int output_file = open(output_filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  for (int i = 0; i < 8; i++) {
    uint32_to_hex(hashes[i], result);
    int er = write(output_file, result, 8);  // err(__LINE__);
  }
}
