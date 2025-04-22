#include "util.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#else
#include <endian.h>
#endif


#include <string.h>

/* when reading long integers, never read more than this many bytes: */
#define MPZ_MAX_LEN 1024

/* Like read(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xread(int fd, void *buf, size_t nBytes)
{
	do {
		ssize_t n = read(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) perror("read"), abort();
		buf = (char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

/* Like write(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xwrite(int fd, const void *buf, size_t nBytes)
{
	do {
		ssize_t n = write(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) perror("write"), abort();
		buf = (const char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

size_t serialize_mpz(int fd, mpz_t x)
{
	/* format:
	 * +--------------------------------------------+---------------------------+
	 * | nB := numBytes(x) (little endian, 4 bytes) | bytes(x) (l.e., nB bytes) |
	 * +--------------------------------------------+---------------------------+
	 * */
	/* NOTE: for compatibility across different systems, we always write integers
	 * little endian byte order when serializing.  Note also that mpz_sizeinbase
	 * will return 1 if x is 0, so nB should always be the correct byte count. */
	size_t nB;
	unsigned char* buf = Z2BYTES(NULL,&nB,x);
	/* above has allocated memory for us, and stored the size in nB.  HOWEVER,
	 * if x was 0, then no allocation would be done, and buf will be NULL: */
	if (!buf) {
		nB = 1;
		buf = malloc(1);
		*buf = 0;
	}
	assert(nB < 1LU << 32); /* make sure it fits in 4 bytes */
	LE(nB);
	xwrite(fd,&nB_le,4);
	xwrite(fd,buf,nB);
	free(buf);
	return nB+4; /* total number of bytes written to fd */
}

int deserialize_mpz(mpz_t x, int fd)
{
	/* we assume buffer is formatted as above */
	uint32_t nB_le;
	xread(fd,&nB_le,4);
	size_t nB = le32toh(nB_le);
	if (nB > MPZ_MAX_LEN) return -1;
	unsigned char* buf = malloc(nB);
	xread(fd,buf,nB);
	BYTES2Z(x,buf,nB);
	return 0;
}

//add digital signs to assure security
int sign_with_rsa(const char* priv_key_path, const char* msg, unsigned char** sig)
{
    FILE* fp = fopen(priv_key_path, "r");
    if (!fp) {
        fprintf(stderr, "Could not open private key file: %s\n", priv_key_path);
        return -1;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to read private key.\n");
        return -1;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, msg, strlen(msg));

    *sig = malloc(EVP_PKEY_size(pkey));
    unsigned int sig_len = 0;

    if (!EVP_SignFinal(ctx, *sig, &sig_len, pkey)) {
        fprintf(stderr, "Failed to generate signature.\n");
        sig_len = -1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return sig_len;
}

//verify sign
int verify_rsa_signature(const char* pub_key_path, const char* msg, unsigned char* sig, unsigned int sig_len)
{
    FILE* fp = fopen(pub_key_path, "r");
    if (!fp) {
        fprintf(stderr, "Could not open public key file: %s\n", pub_key_path);
        return 0;
    }

    EVP_PKEY* pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pubkey) {
        fprintf(stderr, "Failed to read public key.\n");
        return 0;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, msg, strlen(msg));

    int result = EVP_VerifyFinal(ctx, sig, sig_len, pubkey);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return result == 1;
}
