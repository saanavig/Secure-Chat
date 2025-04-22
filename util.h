#pragma once
#include <gmp.h>

/* convenience macros */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
/* these will read/write integers from byte arrays where the
 * least significant byte is first (little endian bytewise). */
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,len,-1,1,0,0,x)
#define LE(x) uint32_t x##_le = htole32((uint32_t)x)

#ifndef UTIL_H
#define UTIL_H

/* utility functions */

/** write an mpz_t as an unambiguous sequence of bytes.
 * @param fd is the file descriptor to write to.  Must be opened for writing.
 * @param x is the integer to serialize and write.
 * @return total number of bytes written, or 0 to indicate failure.
 * */
size_t serialize_mpz(int fd, mpz_t x);

/** inverse operation of serialize_mpz */
int deserialize_mpz(mpz_t x, int fd);

/** Like read(), but retry on EINTR and EWOULDBLOCK */
void xread(int fd, void *buf, size_t nBytes);

/** Like write(), but retry on EINTR and EWOULDBLOCK */
void xwrite(int fd, const void *buf, size_t nBytes);

/** RSA signing and verification (declarations) */
int sign_with_rsa(const char* priv_key_path, const char* msg, unsigned char** sig);
int verify_rsa_signature(const char* pub_key_path, const char* msg, unsigned char* sig, unsigned int sig_len);

#endif // UTIL_H
