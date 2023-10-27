#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <math.h>
#include <mpi.h>
#include <openssl/des.h>

int NUMBER_OF_CHARACTERS = 95;

static inline void increment_ascii(int *ascii)
{
  int remember = 0;
  ascii[4] += 1;
  for (int i = 4; i >= 0; i--)
  {
    ascii[i] += remember;
    if (ascii[i] <= 126)
    {
      break;
    }
    ascii[i] = 32;
    remember = 1;
  }
}

static inline void ascii_to_string(int *ascii, char *letter)
{
  for (int i = 0; i < 5; i++)
  {
    letter[i] = ascii[i];
  }
}

static inline void order_to_ascii(long int order, int *ascii)
{
  long int quotient = order;
  int remainder = 0;

  int isLastDigit = 0;

  for (int i = 4; i >= 0; i--)
  {
    isLastDigit = (i == 4);
    remainder = quotient % NUMBER_OF_CHARACTERS;
    quotient = quotient / NUMBER_OF_CHARACTERS;

    if (remainder != 0)
    {
      ascii[i] = 32 + remainder - isLastDigit;
    }

    if (quotient <= 94)
    {
      ascii[i - 1] = 32 + quotient;
      break;
    }
  }
}

/**
 * decrypt_des - decrypts a block of memory with the DES algorithm
 * @param key - character string containing decryption key
 * @param msg - array of bytes to decrypt
 * @param size - size of msg
 * @returns decrypted array of bytes
 */
char *decrypt_des(char *key, char *msg, int size)
{
  static char *res;
  int n = 0;

  DES_cblock key2;
  DES_key_schedule schedule;

  res = (char *)malloc(size);

  /* Prepare the key for use with DES_cfb64_encrypt */
  memcpy(key2, key, 8);
  DES_set_odd_parity(&key2);
  DES_set_key_checked(&key2, &schedule);

  /* Decryption occurs here */
  DES_cfb64_encrypt((unsigned char *)msg, (unsigned char *)res,
                    size, &schedule, &key2, &n, DES_DECRYPT);
  return (res);
}

char *decrypt_message(char *password, char *filepath)
{
  char *buf; // buffers for encrypt/decrypt
  struct stat st;
  int rfd; // file descriptors

  if (stat(filepath, &st) != 0)
  {
    perror("stat");
    exit(1);
  }
  // allocate a buffer for the input file
  buf = malloc(st.st_size + 1);
  // open input file
  if ((rfd = open(filepath, O_RDONLY)) == -1)
  {
    perror("open (reading)");
    exit(1);
  }
  read(rfd, buf, st.st_size); // read entire file into buffer
  buf[st.st_size] = '\0';     // null terminate string

  close(rfd);
  free(buf);

  return decrypt_des(password, buf, st.st_size);
}

int main(int argc, char **argv)
{
  double start, end;
  int rank, size;

  MPI_Init(&argc, &argv);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);
  if (rank == 0)
    printf("starting run with %d processes\n", size);

  start = MPI_Wtime();

  // intialize variables

  // char password[14] = "N0NSjOXiqCyGE";
  // char salt[3] = "N0";
  char password[14] = "wDqVEHozzDT1E";
  char salt[3] = "wD";

  char letter[6] = "xxxxx";
  password[13] = '\0';
  salt[2] = '\0';
  letter[5] = '\0';
  char *hash_code = NULL;
  int ascii[5] = {32, 32, 32, 32, 32};
  char *decrypted_password = NULL;

  // find starting point of each processor
  long int start_order;
  long int number_of_work = pow(95, 5) / size;
  long int communication_threshold = number_of_work / 30;
  int communication_result = 0;

  // calculating remainder
  int remainder = (int)pow(95, 5) % size;
  int hasRemainder = (rank < remainder);
  long int remainder_order;
  int remainder_ascii[5];
  char remainder_letter[6] = "xxxxx";
  remainder_letter[5] = '\0';

  if (hasRemainder)
  {
    remainder_order = number_of_work * size + rank;
    order_to_ascii(remainder_order, remainder_ascii);
    ascii_to_string(remainder_ascii, remainder_letter);
  }

  start_order = rank * number_of_work;
  order_to_ascii(start_order, ascii);
  long int count = 0;

  while (count < number_of_work)
  {
    // convert ascii to string and hash it
    ascii_to_string(ascii, letter);
    hash_code = DES_crypt(letter, salt);

    // check if it is the encrypted password
    if (strcmp(hash_code, password) == 0)
    {
      printf("The password is: %s\n\n", letter);
      decrypted_password = letter;
      int one = 1;
      // communicate if find password and break
      MPI_Allreduce(&one, &communication_result, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
      break;
    }

    // communication if reach certain point
    if (count % communication_threshold == 0)
    {
      int zero = 0;
      MPI_Allreduce(&zero, &communication_result, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
      if (communication_result)
        break; // if password found, break
    }

    // check next combination
    increment_ascii(ascii);
    count++;
  }

  // if has remainder and did not found password
  if (hasRemainder && !communication_result)
  {
    hash_code = DES_crypt(remainder_letter, salt);
    if (strcmp(hash_code, password) == 0)
    {
      printf("The password is: %s\n\n", remainder_letter);
      decrypted_password = remainder_letter;
    }
  }

  MPI_Barrier(MPI_COMM_WORLD);
  end = MPI_Wtime();

  // decrypt message
  if (decrypted_password != NULL)
  {
    printf("finish\n");
    printf("elapsed time: %7.4f s\n", end - start);
  }

  MPI_Finalize();
}
