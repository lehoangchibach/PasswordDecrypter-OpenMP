#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/des.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/**
 * encrypt_des - encrypts a block of memory with the DES algorithm
 * @param key - character string containing encryption key
 * @param msg - array of bytes to encrypt
 * @param size - size of msg
 * @returns encrypted array of bytes
 */
char *encrypt_des(char *key, char *msg, int size)
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

  /* Encryption occurs here */
  DES_cfb64_encrypt((unsigned char *)msg, (unsigned char *)res,
                    size, &schedule, &key2, &n, DES_ENCRYPT);
  return (res);
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

/*
 *  main function
 */
int main(int argc, char **argv)
{
  char pass[9];        // password to use as key
  char *buf, *cbuf;    // buffers for encrypt/decrypt
  char *cpass;         // encrypted password
  char salt[3] = "AA"; // crypt salt
  struct stat st;
  char *fileext = ".des";     // file extension for encrypted file
  int rfd, wfd;               // file descriptors
  char *filename, *cfilename; // plain an encrypted filenames
  int len, extlen, clen;      // buffer lengths

  /*
   * check arguments for sanity
   */
  if (argc != 4)
  {
    printf("\tusage: crypter <filename> <salt> <password>\n");
    exit(1);
  }

  /*
   * encrypt password string
   */
  if (strnlen(argv[2], sizeof(salt)) >= (sizeof(salt)))
  {
    printf("salt must be shorter than %lu characters\n", sizeof(salt));
    exit(1);
  }
  strncpy(salt, argv[2], sizeof(salt) - 1);

  if (strnlen(argv[3], sizeof(pass)) >= (sizeof(pass)))
  {
    printf("password must be shorter than %lu characters\n", sizeof(pass));
    exit(-1);
  }
  strncpy(pass, argv[3], sizeof(pass) - 1);

  pass[sizeof(pass) - 1] = '\0'; // null terminate string
  cpass = DES_crypt(pass, salt);
  printf("crypted passwd is: \"%s\"\n", cpass);

  /*
   * read file, encrypt with password string and store in output file
   */
  filename = argv[1];
  len = strnlen(filename, 1024); // max length 1024
  extlen = strnlen(fileext, 1024);
  clen = len + extlen + 1; // account for \0 terminator
  cfilename = malloc(clen);
  strncpy(cfilename, filename, len);
  strncat(cfilename, fileext, extlen); // append .des to input file
  printf("source: %s crypted: %s\n", filename, cfilename);

  // get input file size
  if (stat(filename, &st) != 0)
  {
    perror("stat");
    exit(1);
  }

  // allocate a buffer for the input file
  buf = malloc(st.st_size + 1);

  // open input file
  if ((rfd = open(filename, O_RDONLY)) == -1)
  {
    perror("open (reading)");
    exit(1);
  }

  // open output file
  if ((wfd = open(cfilename, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode)) == -1)
  {
    perror("open (writing)");
    exit(1);
  }

  read(rfd, buf, st.st_size); // read entire file into buffer
  buf[st.st_size] = '\0';     // null terminate string

  // encrypt file data
  cbuf = encrypt_des(pass, buf, st.st_size);

  // save it in output file
  write(wfd, cbuf, st.st_size);

  close(rfd);
  close(wfd);

  free(cfilename);
  free(buf);
  free(cbuf);
}
