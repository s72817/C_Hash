#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/md4.h>
#include <openssl/blowfish.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BFCBC EVP_bf_cbc()
#define EVPMD4 EVP_md4()
#define EVPSHA EVP_sha1()
#define IVLENGTH EVP_CIPHER_iv_length(BFCBC)


void hex_output(unsigned char* buffer)
{
  int i;

  printf("Hex: ");
  for(i = 0; i < strlen(buffer); i++)
  {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

// Quelle: Praktikum 3
void read_file(unsigned char **buffer, long *filesize, char *file)
{
  FILE *fin = fopen(file, "r");

  fseek(fin, 0L, SEEK_END);
  *filesize = ftell(fin);
  rewind(fin);
  *buffer=malloc(*filesize);
  fread(*buffer, *filesize, 1, fin);
  fclose(fin);
}

void write_into_file(char *file, unsigned char *buffer, long filesize)
{
  FILE *fout = fopen(file, "w");
  fwrite(buffer, sizeof(char), filesize, fout);
  fclose(fout);
}


// alternative to DigestVerify...
int evp_verify(unsigned char *cipher, EVP_PKEY* pubkey, unsigned char *signature, int signature_filesize)
{
  unsigned char *buffer;
  long filesize;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();

  read_file(&buffer, &filesize, cipher);

  EVP_VerifyInit_ex(ctx, EVPSHA, NULL);
  EVP_VerifyUpdate(ctx, buffer, filesize);

  return EVP_VerifyFinal(ctx, signature, signature_filesize, pubkey);
}

unsigned char *evp_decrypt(unsigned char *buffer, long *filesize, unsigned char *pk, unsigned char *iv)
{
  EVP_CIPHER_CTX ctx;
  unsigned char *plaintext;
  int plaintext_len = 0;
  int len = 0;

  plaintext = malloc(*filesize+1);
  plaintext[*filesize] = '\0';

  EVP_DecryptInit(&ctx, BFCBC, pk, iv);
  EVP_DecryptUpdate(&ctx, plaintext, &plaintext_len, buffer, *filesize);
  EVP_DecryptFinal(&ctx, plaintext + plaintext_len, &len);

  *filesize = plaintext_len + len;

  return plaintext;
}

// Quelle: Praktikum 3
unsigned char *hash_as_md4(unsigned char *data, long size)
{
  EVP_MD_CTX ctx;
  unsigned char md[MD4_DIGEST_LENGTH];
  unsigned char *sXXXXXhash = "sXXXXX-hash.bin";
  int i;
  int md_len;
  static char buf[80];

  EVP_DigestInit(&ctx, EVPMD4);
  EVP_DigestUpdate(&ctx, data, size);
  EVP_DigestFinal(&ctx, md, &md_len);

  write_into_file(sXXXXXhash, md, md_len);

  for (i=0; i<MD4_DIGEST_LENGTH; i++)
  {
    sprintf(&(buf[i]), "%c", md[i]);
  }

  return buf;
}

void task_3(unsigned char *verified_file_buffer, long size)
{
  unsigned char *hash_buffer;

  // get hash with md4 algorithm
  hash_buffer = hash_as_md4(verified_file_buffer, size);
  hex_output(hash_buffer);
}

unsigned char *task_2(unsigned char *verified_file, long *filesize)
{
  long filesize_cipher;
  long private_key_filesize;

  int i;
  int iter_pk;
  int iter_iv;

  unsigned char *private_key_buffer;
  unsigned char *verified_file_buffer;
  unsigned char *private_key_file = "sXXXXX-key.bin";
  unsigned char IV[IVLENGTH];

  // get private key
  read_file(&private_key_buffer, &filesize_cipher, private_key_file);
  private_key_filesize = strlen(private_key_buffer);
  unsigned char private_key[private_key_filesize-IVLENGTH];

  iter_pk = 0;
  iter_iv = private_key_filesize-IVLENGTH-1;
  
  // FIXME: doesnt work
  for(i = 0; i < private_key_filesize; i++)
  {
    if(i < private_key_filesize-IVLENGTH-1)
    {
      sprintf(&private_key[iter_pk++], "%c", private_key_buffer[i]);
    }
    else
    {
      sprintf(&IV[iter_iv++], "%c", private_key_buffer[i]);
    }
  }

  // decrypt verified cipher buffer
  read_file(&verified_file_buffer, &filesize_cipher, verified_file);
  verified_file_buffer = evp_decrypt(verified_file_buffer, &filesize_cipher, private_key, IV);
  write_into_file("loesung.pdf", verified_file_buffer, filesize_cipher);

  *filesize = filesize_cipher;

  return verified_file_buffer;
}

void task_1(unsigned char **verified_file)
{
  EVP_PKEY* public_key;
  FILE *file_public_key;

  long filesize_signature;

  unsigned char *signature_buffer;
  unsigned char *signature_file = "sXXXXX-sig.bin";
  unsigned char *cipher_file01 = "sXXXXX-cipher01.bin";
  unsigned char *cipher_file02 = "sXXXXX-cipher02.bin";
  unsigned char *cipher_file03 = "sXXXXX-cipher03.bin";

  // get pub key
  file_public_key = fopen("pubkey.pem", "r");
  public_key = PEM_read_PUBKEY(file_public_key, NULL, NULL, NULL);
  fclose(file_public_key);

  // get signature
  read_file(&signature_buffer, &filesize_signature, signature_file);

  // FIXME: bad stile
  if(evp_verify(cipher_file01, public_key, signature_buffer, filesize_signature))
  {
    *verified_file = cipher_file01;
  }
  else if(evp_verify(cipher_file02, public_key, signature_buffer, filesize_signature))
  {
    *verified_file = cipher_file02;
  }
  else if(evp_verify(cipher_file03, public_key, signature_buffer, filesize_signature))
  {
    *verified_file = cipher_file03;
  }
  else
  {
    printf("No file is verified!\n");
    exit(EXIT_FAILURE);
  }
  printf("verified ok: %s\n", *verified_file);
}


int main(int argc, char *argv[])
{
  unsigned char *hash_buffer;
  unsigned char *verified_file;
  unsigned char *verified_file_buffer;
  unsigned char *sXXXXXhash = "sXXXXX-hash.bin";
  long filesize;

  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();

  task_1(&verified_file);

  verified_file_buffer = task_2(verified_file, &filesize);

  task_3(verified_file_buffer, filesize);

  EVP_cleanup();
  ERR_free_strings();

  exit(EXIT_SUCCESS);
}
