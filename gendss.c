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
#include "signkey.h"
#include "bignum.h"
#include "random.h"
#include "buffer.h"
#include "gendss.h"
#include "dss.h"

#define QSIZE 20 /* 160 bit */

/* This is just a test */

#ifdef DROPBEAR_DSS

static void getq(dropbear_dss_key *key);
static void getp(dropbear_dss_key *key, unsigned int size);
static void getg(dropbear_dss_key *key);
static void getx(dropbear_dss_key *key);
static void gety(dropbear_dss_key *key);

dropbear_dss_key * gen_dss_priv_key(unsigned int size) {

	dropbear_dss_key *key;

	key = m_malloc(sizeof(*key));

	key->p = (fp_int*)m_malloc(sizeof(fp_int));
	key->q = (fp_int*)m_malloc(sizeof(fp_int));
	key->g = (fp_int*)m_malloc(sizeof(fp_int));
	key->y = (fp_int*)m_malloc(sizeof(fp_int));
	key->x = (fp_int*)m_malloc(sizeof(fp_int));
	m_fp_init_multi(key->p, key->q, key->g, key->y, key->x, NULL);
	
	seedrandom();
	
	getq(key);
	getp(key, size);
	getg(key);
	getx(key);
	gety(key);

	return key;
	
}

static void getq(dropbear_dss_key *key) {

	char buf[QSIZE];

	/* 160 bit prime */
	genrandom(buf, QSIZE);
	buf[0] |= 0x80; /* top bit high */
	buf[QSIZE-1] |= 0x01; /* bottom bit high */

	bytes_to_fp(key->q, buf, QSIZE);

	/* 18 rounds are required according to HAC */
	if (fp_prime_next_prime(key->q, 18, 0) != FP_OKAY) {
		fprintf(stderr, "DSS key generation failed\n");
		exit(1);
	}
}

static void getp(dropbear_dss_key *key, unsigned int size) {

	DEF_FP_INT(tempX);
	DEF_FP_INT(tempC);
	DEF_FP_INT(tempP);
	DEF_FP_INT(temp2q);
	int result;
	unsigned char *buf;

	m_fp_init_multi(&tempX, &tempC, &tempP, &temp2q, NULL);


	/* 2*q */
	fp_mul_d(key->q, 2, &temp2q);
	
	buf = (unsigned char*)m_malloc(size);

	result = 0;
	do {
		
		genrandom(buf, size);
		buf[0] |= 0x80; /* set the top bit high */

		/* X is a random fp_int */
		bytes_to_fp(&tempX, buf, size);

		/* C = X mod 2q */
		if (fp_mod(&tempX, &temp2q, &tempC) != FP_OKAY) {
			fprintf(stderr, "DSS key generation failed\n");
			exit(1);
		}

		/* P = X - (C - 1) = X - C + 1*/
		fp_sub(&tempX, &tempC, &tempP);
		
		fp_add_d(&tempP, 1, key->p);

		/* now check for prime, 5 rounds is enough according to HAC */
		/* result == 1  =>  p is prime */
		if (fp_prime_is_prime(key->p, 5, &result) != FP_OKAY) {
			fprintf(stderr, "DSS key generation failed\n");
			exit(1);
		}
	} while (!result);

	fp_zero(&tempX);
	fp_zero(&tempC);
        fp_zero(&tempP);
        fp_zero(&temp2q);
	m_burn(buf, size);
	m_free(buf);
}

static void getg(dropbear_dss_key * key) {

	DEF_FP_INT(div);
	DEF_FP_INT(h);
	DEF_FP_INT(val);

	m_fp_init_multi(&div, &h, &val, NULL);

	/* get div=(p-1)/q */
	fp_sub_d(key->p, 1, &val);
	fp_div(&val, key->q, &div, NULL);

	/* initialise h=1 */
	fp_set(&h, 1);
	do {
		/* now keep going with g=h^div mod p, until g > 1 */
		if (fp_exptmod(&h, &div, key->p, key->g) != FP_OKAY) {
			fprintf(stderr, "DSS key generation failed\n");
			exit(1);
		}

		fp_add_d(&h, 1, &h);
	
	} while (fp_cmp_d(key->g, 1) != FP_GT);

	fp_zero(&div);
	fp_zero(&h);
	fp_zero(&val);
}

static void getx(dropbear_dss_key *key) {

	gen_random_fpint(key->q, key->x);
}

static void gety(dropbear_dss_key *key) {

	if (fp_exptmod(key->g, key->x, key->p, key->y) != FP_OKAY) {
		fprintf(stderr, "DSS key generation failed\n");
		exit(1);
	}
}

#endif /* DROPBEAR_DSS */
