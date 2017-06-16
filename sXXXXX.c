#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/md4.h>
#include <openssl/blowfish.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IVLENGTH 8

void hex_output(unsigned char* buffer) {
    int i;

    printf("Hex: ");
    for(i = 0; i < strlen(buffer); i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}


// Quelle: Praktikum 3
void read_file(unsigned char **buffer, long *filesize, char *file) {
    FILE *fin;

    if ((fin = fopen(file, "r")) == NULL){
        printf("Error opening %s.\n", file);
        exit(EXIT_FAILURE);
    }
    fseek(fin, 0L, SEEK_END);
    *filesize = ftell(fin);
    rewind(fin);

    if (!(*buffer=malloc(*filesize))) {
        printf("Memory exhausted. Stop.\n");
        exit(EXIT_FAILURE);
    }
    fread(*buffer, *filesize, 1, fin);

    fclose(fin);
}

void write_into_file(char *file, unsigned char *buffer, long filesize) {
    FILE *fout;

    if ((fout = fopen(file, "w")) == NULL) {
        printf("Error opening file!\n");
        exit(EXIT_FAILURE);
    }
    fwrite(buffer, sizeof(char), filesize, fout);
    fclose(fout);
}


// alternative to DigestVerify...
int evp_verify(unsigned char *cipher, EVP_PKEY* pubkey, unsigned char *signature, int signature_filesize) {
    unsigned char *buffer;
    long filesize;
    const EVP_MD* md = EVP_get_digestbyname("SHA1");
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    read_file(&buffer, &filesize, cipher);

    EVP_VerifyInit_ex(ctx, md, NULL);
    EVP_VerifyUpdate(ctx, buffer, filesize);

    return EVP_VerifyFinal(ctx, signature, signature_filesize, pubkey); // 1 is true
}

unsigned char *evp_decrypt(unsigned char *buffer, long filesize, unsigned char *private_key, unsigned char *iv) {
    EVP_CIPHER_CTX ctx;
    unsigned char *out_buf = malloc(filesize);
    int outbuf_length1 = 0, outbuf_length2 = 0;

    EVP_DecryptInit(&ctx, EVP_bf_cbc(), private_key, iv);
    EVP_DecryptUpdate(&ctx, out_buf, &outbuf_length1, buffer, filesize);
    EVP_DecryptFinal(&ctx, out_buf + outbuf_length1, &outbuf_length2);

    write_into_file("loesung.pdf", out_buf, outbuf_length1 + outbuf_length2);

    return out_buf;
}

// Quelle: Praktikum 3
unsigned char *hash_as_md4(unsigned char *data) {
    EVP_MD_CTX ctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    int i;
    static char buf[80];

    EVP_DigestInit(&ctx, EVP_md4());
    EVP_DigestUpdate(&ctx, data, strlen(data));
    EVP_DigestFinal(&ctx, md, NULL);

    for (i=0; i<MD4_DIGEST_LENGTH; i++) {
    	sprintf(&(buf[i]), "%c", md[i]);
    }

    return buf;
}

int main(int argc, char *argv[]) {
    EVP_PKEY* public_key;
    FILE *file_public_key;

    long filesize_cipher;
    long filesize_signature;
    long private_key_filesize;

    int i;
    int iter_pk;
    int iter_iv;
    int retc = 0;

    unsigned char *signature_buffer;
    unsigned char *private_key_buffer;
    unsigned char *hash_buffer;
    unsigned char *verified_file;
    unsigned char IV[IVLENGTH];
    unsigned char *verified_file_buffer;
    unsigned char *signature_file = "sXXXXX-sig.bin";
    unsigned char *cipher_file01 = "sXXXXX-cipher01.bin";
    unsigned char *cipher_file02 = "sXXXXX-cipher02.bin";
    unsigned char *cipher_file03 = "sXXXXX-cipher03.bin";
    unsigned char *private_key_file = "sXXXXX-key.bin";
    unsigned char *sXXXXXhash = "sXXXXX-hash.bin";

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    // get pub key
    file_public_key = fopen("pubkey.pem", "r");
    public_key = PEM_read_PUBKEY(file_public_key, NULL, NULL, NULL);
    fclose(file_public_key);

	// get private key
    read_file(&private_key_buffer, &filesize_cipher, private_key_file);
    private_key_filesize = strlen(private_key_buffer);
    unsigned char private_key[private_key_filesize-IVLENGTH];

    // get signature
    read_file(&signature_buffer, &filesize_signature, signature_file);

    // get cipher file contents
    if(evp_verify(cipher_file01, public_key, signature_buffer, filesize_signature)) {
        verified_file = cipher_file01;
	printf("verified ok: %s\n", verified_file);
    }
    else if(evp_verify(cipher_file02, public_key, signature_buffer, filesize_signature)) {
 	verified_file = cipher_file02;
	printf("verified ok: %s\n", verified_file);
    }
    else if(evp_verify(cipher_file03, public_key, signature_buffer, filesize_signature)) {
 	verified_file = cipher_file03;
 	printf("verified ok: %s\n", verified_file);
    }
    else {
 	printf("No file is verified!\n");
 	exit(EXIT_FAILURE);
    }


    // get private key from key.bin
    /*
      FIXME benutze evp zum Splitten des PKs und IVs !!!!!!!!!
     */
    iter_pk = 0;
    iter_iv = private_key_filesize-IVLENGTH-1;
    for(i = 0; i < private_key_filesize; i++) {
    	if(i < private_key_filesize-IVLENGTH-1) sprintf(&private_key[iter_pk++], "%c", private_key_buffer[i]);
    	else sprintf(&IV[iter_iv++], "%c", private_key_buffer[i]);
    }

    // decrypt verified cipher buffer
    read_file(&verified_file_buffer, &filesize_cipher, verified_file);
    verified_file_buffer = evp_decrypt(verified_file_buffer, filesize_cipher, private_key, IV);

    // get hash with md4 algorithm
    hash_buffer = hash_as_md4(verified_file_buffer);
    printf("\nMD4Hash: %s\n", hash_buffer);
    hex_output(hash_buffer);
    write_into_file(sXXXXXhash, hash_buffer, strlen(hash_buffer));

    exit(EXIT_SUCCESS);
}





