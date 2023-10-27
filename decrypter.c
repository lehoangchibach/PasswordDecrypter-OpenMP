#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/des.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

/**
 * decrypt_des - decrypts a block of memory with the DES algorithm
 * @param key - character string containing decryption key
 * @param msg - array of bytes to decrypt
 * @param size - size of msg
 * @returns decrypted array of bytes
 */
char *decrypt_des(char *key, char *msg, int size)
{
    printf("password received: %s\n", key);
    static char *res;
    int n = 0;

    DES_cblock key2;
    DES_key_schedule schedule;

    res = (char *)malloc(size);

    /* Prepare the key for use with DES_cfb64_encrypt */
    memcpy(key2, key, 8);
    printf("key2: %s\n", key2);
    DES_set_odd_parity(&key2);
    DES_set_key_checked(&key2, &schedule);

    /* Decryption occurs here */
    DES_cfb64_encrypt((unsigned char *)msg, (unsigned char *)res,
                      size, &schedule, &key2, &n, DES_DECRYPT);
    return (res);
}

int main()
{
    // decrypt message

    char decrypted_password[9] = "z00m!";
    char decrypted_password[9] = "zyxyz";

    char filepath[18] = "../plans/bach.des";
    // char filepath[23] = "../plans/passwords.des";

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

    printf("password: %s\n", decrypted_password);
    printf("filepath: %s\n", filepath);

    printf("\n\nEncrypted message: \n%s\n\n", buf);
    char *decrypted_message = decrypt_des(decrypted_password, buf, st.st_size + 1);
    decrypted_message[strlen(decrypted_message)] = '\0';
    printf("\n\nSecret Message: \n%s\n", decrypted_message);

    close(rfd);
    free(buf);
}