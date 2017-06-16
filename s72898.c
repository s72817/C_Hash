/*
 * s72898.c
 *
 *  Created on: 06.06.2017
 *      Author: s72898
 *
 *  via shell:
 *  openssl dgst -sha1 -verify pubkey.pem -signature s72898-sig.bin s72898-cipher03.bin
 *  // => Verified OK
 *
 *  USAGE ./s72898_beleg s72898-cipher01.bin s72898-cipher02.bin s72898-cipher03.bin 
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>

#define IV_LEN 8
#define S72898_HASH_BIN "s72898-hash.bin"

typedef unsigned char UC;


EVP_PKEY *get_public_key(char *filename) {
    FILE *f_pubkey;
    EVP_PKEY *public_key;

    f_pubkey = fopen(filename, "rb");
    public_key = PEM_read_PUBKEY(f_pubkey, NULL, NULL, NULL);
    fclose(f_pubkey);

    return public_key;
}


// @Informationssicherheit
UC *get_file_content(char *source, long *f_size) {
    FILE *fin;
    UC *buf;

    if ((fin = fopen(source, "r")) == NULL){
        printf("Error opening %s.\n", source);
        exit(EXIT_FAILURE);
    }
    fseek(fin, 0L, SEEK_END);
    *f_size = ftell(fin);
    rewind(fin);

    if (!(buf=malloc(*f_size))) {
        printf("Memory exhausted. Stop.\n");
        exit(EXIT_FAILURE);
    }
    fread(buf, *f_size, 1, fin);

    fclose(fin);
    return buf;
}


void set_file_with_decrypted_content(char *filename, UC *content, long f_size) {
    FILE *fout = fopen(filename, "w");

    if (fout == NULL) {
        printf("Error opening file!\n");
        exit(EXIT_FAILURE);
    }

    fwrite(content, sizeof(char), f_size, fout);
    fclose(fout);
}


void set_file_with_hash_content(char *filename, UC *content, long filesize) {
    FILE *fout = fopen(filename, "w");

    if (fout == NULL) {
        printf("Error opening file!\n");
        exit(EXIT_FAILURE);
    }

    //fwrite(content,sizeof(char),filesize,fout);

    fputs(content, fout);
    fclose(fout);
}


int evp_verify(
	UC *data,
	int data_len,
	UC *signature,
	int f_size_signature,
	EVP_PKEY* pkey) {

    const EVP_MD* md = EVP_get_digestbyname("SHA1"); // ENGINE
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, md, NULL);
    int result;

    EVP_VerifyInit_ex(ctx, md, NULL);
    EVP_VerifyUpdate(ctx, data, data_len);
    result = EVP_VerifyFinal(ctx, signature, f_size_signature, pkey);

    EVP_MD_CTX_destroy(ctx);

    return result;
}


UC *decrypt_blowfish(UC *in_data, UC *private_key, UC *iv, long *f_size_cipher) {
    EVP_CIPHER_CTX ctx;
    UC *out_data = malloc(*f_size_cipher);
    int out_len1 = 0, out_len2 = 0;

    EVP_DecryptInit(&ctx, EVP_bf_cfb(), private_key, iv);
    EVP_DecryptUpdate(&ctx, out_data, &out_len1, in_data, *f_size_cipher);
    EVP_DecryptFinal(&ctx, out_data, &out_len2);

    set_file_with_decrypted_content("decrypt.pdf", out_data, out_len1 + out_len2);

    *f_size_cipher = (long) (out_len1 + out_len2);

    return out_data;
}


// @Informationssicherheit
static char *printf_as_hex(unsigned char *md) {
    int i;
    static char buf[80]; // FIXME is value necessary?

    for (i=0; i<SHA384_DIGEST_LENGTH; i++) {
        sprintf(&(buf[i*2]), "%02X", md[i]);
    }

    return buf;
}


void sha384sum(UC *content, long f_size_cipher) {
    EVP_MD_CTX c;
    UC md[EVP_MAX_MD_SIZE];

    if ((EVP_DigestInit(&c, EVP_sha384())) == 0) exit(EXIT_FAILURE);
    if ((EVP_DigestUpdate(&c, content, f_size_cipher)) == 0) exit(EXIT_FAILURE);
    if ((EVP_DigestFinal(&c, md, NULL)) == 0) exit(EXIT_FAILURE);

    printf("HASH: %s\n", md);

    set_file_with_hash_content(S72898_HASH_BIN, md, f_size_cipher);

    printf("%s", printf_as_hex(md));
}



int main(int argc, char *argv[]) {
    UC *file_content_buffer;
    UC *signature;
    UC *private_key_content;
    UC *hash_as_hex;
    UC *verified_input_argument;
    UC iv[IV_LEN]; // initialization vector
    UC *decrypted_content;
    UC *encrypted_content_from_verified_cipher;
    long f_size_cipher, f_size_signature;
    int i, j, retc;
    EVP_PKEY* public_key;

    // get cipher files as args
    if (argc != 4) {
        printf("Usage: %s <cipher_file1> <cipher_file2> <cipher_file3>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();



    /****************** Task 1 *******************/

    signature = get_file_content("s72898-sig.bin", &f_size_signature);
    public_key = get_public_key("pubkey.pem");

    for(i = 1; i < argc; i++) {
    	file_content_buffer = get_file_content(argv[i], &f_size_cipher);
    	retc = evp_verify(file_content_buffer, f_size_cipher, signature, f_size_signature, public_key);

    	if(retc) {
    	    printf("Aufgabe 1 - Verified ok: %s\n", argv[i]);
    	    verified_input_argument = argv[i];
    	}
    }
    if(!verified_input_argument) {
    	printf("No argument is verified!");
    	exit(EXIT_SUCCESS);
    }

    EVP_PKEY_free(public_key);

    /************************************************/


    /****************** Task 2 *******************/

    private_key_content = get_file_content("s72898-key.bin", &f_size_cipher);
    long private_key_content_length = strlen(private_key_content);
    UC private_key[private_key_content_length-IV_LEN];

    /* split private key + IV and write into two separate buffers */
    for(i = 0, j = 0; i < private_key_content_length-IV_LEN-1; i++, j++) {
    	sprintf(&private_key[j], "%c", private_key_content[i]);
    }
    for(i = private_key_content_length-IV_LEN-1, j = 0; i < private_key_content_length; i++, j++) {
    	sprintf(&iv[j], "%c", private_key_content[i]);
    }

    encrypted_content_from_verified_cipher = get_file_content(verified_input_argument, &f_size_cipher);

    // is setting content into "decrypt.pdf"
    decrypted_content = decrypt_blowfish(encrypted_content_from_verified_cipher, private_key, iv, &f_size_cipher);

    /************************************************/


    /****************** Task 3 *******************/

    // is setting hash into s72898-hash.bin
    sha384sum(decrypted_content, f_size_cipher);
    hash_as_hex = get_file_content(S72898_HASH_BIN, &f_size_cipher);
    printf("\n%s", printf_as_hex(hash_as_hex));

    /************************************************/

    exit(EXIT_SUCCESS);
}
