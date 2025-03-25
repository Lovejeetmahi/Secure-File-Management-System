#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/aes.h>

#define KEY "0123456789abcdef" // 16-byte key

void encrypt(const char *input, const char *output) {
    AES_KEY encryptKey;
    AES_set_encrypt_key((const unsigned char*)KEY, 128, &encryptKey);
    
    FILE *in = fopen(input, "rb");
    FILE *out = fopen(output, "wb");
    
    unsigned char buffer[16];
    unsigned char encrypted[16];
    
    while (fread(buffer, 1, 16, in) > 0) {
        AES_encrypt(buffer, encrypted, &encryptKey);
        fwrite(encrypted, 1, 16, out);
    }
    fclose(in);
    fclose(out);
}

void decrypt(const char *input, const char *output) {
    AES_KEY decryptKey;
    AES_set_decrypt_key((const unsigned char*)KEY, 128, &decryptKey);
    
    FILE *in = fopen(input, "rb");
    FILE *out = fopen(output, "wb");
    
    unsigned char buffer[16];
    unsigned char decrypted[16];
    
    while (fread(buffer, 1, 16, in) > 0) {
        AES_decrypt(buffer, decrypted, &decryptKey);
        fwrite(decrypted, 1, 16, out);
    }
    fclose(in);
    fclose(out);
}

void write_secure_file(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    fprintf(file, "%s", data);
    fclose(file);
    encrypt(filename, "encrypted_file.dat");
}

void read_secure_file(const char *filename) {
    decrypt("encrypted_file.dat", filename);
    FILE *file = fopen(filename, "r");
    char content[256];
    fgets(content, sizeof(content), file);
    fclose(file);
    printf("Decrypted File Content: %s\n", content);
}

void view_metadata(const char *filename) {
    struct stat statbuf;
    if (stat(filename, &statbuf) == 0) {
        printf("Size: %ld bytes\n", statbuf.st_size);
        printf("Last Modified: %ld\n", statbuf.st_mtime);
        printf("Created: %ld\n", statbuf.st_ctime);
    } else {
        printf("File not found.\n");
    }
}

int main() {
    const char *file_name = "secure_data.txt";
    write_secure_file(file_name, "Confidential Data");
    read_secure_file(file_name);
    view_metadata("encrypted_file.dat");
    return 0;
}
