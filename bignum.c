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

/* Contains helper functions for fp_int handling */

#include "includes.h"
#include "dbutil.h"

/* wrapper for fp_init, failing fatally on errors (memory allocation) */
void m_fp_init(fp_int *fp) {

	fp_init(fp);
}

/* simplified duplication of bn_fp_multi's fp_init_multi, but die fatally
 * on error */
void m_fp_init_multi(fp_int *fp, ...) 
{
    fp_int* cur_arg = fp;
    va_list args;

    va_start(args, fp);        /* init args to next argument from caller */
    while (cur_arg != NULL) {
        fp_init(cur_arg);
        cur_arg = va_arg(args, fp_int*);
    }
    va_end(args);
}

/* simplified duplication of bn_fp_multi's fp_init_multi, but die fatally
 * on error */
void m_fp_zero_multi(fp_int *fp, ...) 
{
    fp_int* cur_arg = fp;
    va_list args;

    va_start(args, fp);        /* init args to next argument from caller */
    while (cur_arg != NULL) {
        fp_zero(cur_arg);
        cur_arg = va_arg(args, fp_int*);
    }
    va_end(args);
}

void bytes_to_fp(fp_int *fp, const unsigned char* bytes, unsigned int len) {

	fp_read_unsigned_bin(fp, (unsigned char*)bytes, len);
}

/* hash the ssh representation of the fp_int fp */
void sha1_process_fp(hash_state *hs, fp_int *fp) {

	int i;
	buffer * buf;

	buf = buf_new(512 + 20); /* max buffer is a 4096 bit key, 
								plus header + some leeway*/
	buf_putfpint(buf, fp);
	i = buf->pos;
	buf_setpos(buf, 0);
	sha1_process(hs, buf_getptr(buf, i), i);
	buf_free(buf);
}
