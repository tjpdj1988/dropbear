/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "dbutil.h"
#include "bignum.h"
#include "random.h"
#include "rsa.h"
#include "genrsa.h"

#define RSA_E 65537

#ifdef DROPBEAR_RSA

static void getrsaprime(fp_int* prime, fp_int *primeminus, 
		fp_int* rsa_e, unsigned int size);

/* mostly taken from libtomcrypt's rsa key generation routine */
dropbear_rsa_key * gen_rsa_priv_key(unsigned int size) {

	dropbear_rsa_key * key;
	DEF_FP_INT(pminus);
	DEF_FP_INT(qminus);
	DEF_FP_INT(lcm);

	key = m_malloc(sizeof(*key));

	key->e = (fp_int*)m_malloc(sizeof(fp_int));
	key->n = (fp_int*)m_malloc(sizeof(fp_int));
	key->d = (fp_int*)m_malloc(sizeof(fp_int));
	key->p = (fp_int*)m_malloc(sizeof(fp_int));
	key->q = (fp_int*)m_malloc(sizeof(fp_int));

	m_fp_init_multi(key->e, key->n, key->d, key->p, key->q,
			&pminus, &lcm, &qminus, NULL);

	seedrandom();

	fp_set(key->e, RSA_E);

	getrsaprime(key->p, &pminus, key->e, size/2);
	getrsaprime(key->q, &qminus, key->e, size/2);

	fp_mul(key->p, key->q, key->n);

	/* lcm(p-1, q-1) */
	fp_lcm(&pminus, &qminus, &lcm);

	/* de = 1 mod lcm(p-1,q-1) */
	/* therefore d = (e^-1) mod lcm(p-1,q-1) */
	if (fp_invmod(key->e, &lcm, key->d) != FP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

	m_fp_zero_multi(&pminus, &qminus, &lcm, NULL);

	return key;
}	

/* return a prime suitable for p or q */
static void getrsaprime(fp_int* prime, fp_int *primeminus, 
		fp_int* rsa_e, unsigned int size) {

	unsigned char *buf;
	DEF_FP_INT(temp_gcd);

	buf = (unsigned char*)m_malloc(size+1);

	m_fp_init(&temp_gcd);
	do {
		/* generate a random odd number with MSB set, then find the
		   the next prime above it */
		genrandom(buf, size+1);
		buf[0] |= 0x80; /* MSB set */

		bytes_to_fp(prime, buf, size+1);

		/* find the next integer which is prime, 8 round of miller-rabin */
		if (fp_prime_next_prime(prime, 8, 0) != FP_OKAY) {
			fprintf(stderr, "RSA generation failed\n");
			exit(1);
		}

		/* subtract one to get p-1 */
		fp_sub_d(prime, 1, primeminus);
		/* check relative primality to e */
		fp_gcd(primeminus, rsa_e, &temp_gcd);
	} while (fp_cmp_d(&temp_gcd, 1) != FP_EQ); /* while gcd(p-1, e) != 1 */

	/* now we have a good value for result */
	fp_zero(&temp_gcd);
	m_burn(buf, size+1);
	m_free(buf);
}

#endif /* DROPBEAR_RSA */
