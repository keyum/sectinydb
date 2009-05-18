// $Id: RC5M.nc,v 1.4 2004/05/18 19:16:27 nksrules Exp $

/*									tab:4
 * "Copyright (c) 2000-2003 The Regents of the University  of California.  
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the above copyright notice, the following
 * two paragraphs and the author appear in all copies of this software.
 * 
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF
 * CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS."
 *
 * Copyright (c) 2002-2003 Intel Corporation
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached INTEL-LICENSE     
 * file. If you do not find these files, copies can be found by writing to
 * Intel Research Berkeley, 2150 Shattuck Avenue, Suite 1300, Berkeley, CA, 
 * 94704.  Attention:  Intel License Inquiry.
 */

/* Authors: Naveen Sastry
 * Date:    9/29/02
 */

/**
 * @author Naveen Sastry
 */

#warning DEPRECATED MODULE
#warning 
#warning You must increase the CryptoContext size (crypto.h) to 104 bytes
#warning Failure to do so will result in incorrect operation and crashes
#warning 
#warning The RC5 algorithm may be covered by patents restricting its use.
#warning 

includes crypto;

#define RC5_32_P	0xB7E15163L
#define RC5_32_Q	0x9E3779B9L
#define RC5_32_MASK	0xffffffffL

#define RC5_ROUNDS 12

#define rotl32(a,b) fastrol32((a), (b))
#define rotr32(a,b) fastror32((a), (b))

module RC5M {
  provides interface BlockCipher;
  provides interface BlockCipherInfo;
}
implementation
{
  // 2 * (ROUNDS +1) * 4 
  // 2 * 13 * 4 = 104 bytes
   typedef struct RC5Context {
    uint32_t skey [2* (RC5_ROUNDS + 1) ];
   } RC5Context;
   
   enum { BSIZE = 8 };
   
  result_t setupKey (CipherContext * context, uint8_t * key);

  void dumpBuffer (char * bufName, uint8_t * buf, uint8_t size)
    {
#ifdef O
      uint8_t i = 0;
      // fixme watch buffer overrun
      char tmp[512];
      for (; i < size; i++) {
        sprintf (tmp + i * 3, "%2x ", (char)buf[i] & 0xff);
      }
      dbg(DBG_CRYPTO, "%s: {%s}\n", bufName, tmp);
#endif
    }
 
  /**
   * Initialize the BlockCipher. 
   *
   * @return Whether initialization was successful. The command may be
   *         unsuccessful if the key size or blockSize are not valid for the
   *         given cipher implementation. 
   */
  command result_t BlockCipher.init(CipherContext * context, uint8_t blockSize,
                                    uint8_t keySize, uint8_t * key)
    {
      // 8 byte blocks only
      if (blockSize != BSIZE) {
        return FAIL;
      }
      return setupKey (context, key);
    }

  /**
   * Encrypts a single block (of blockSize) using the key in the keySize.
   *
   * PROLOGUE: 24 cycles
   * INIT:     48 cycles
   * LOOP:   1680 cycles (12 + fastrol [= 42] + 16) * 2 * RC5_ROUNDS
   * CLOSE:    24 cycles
   * =====================
   *         1776 cycles (avg case)
   * 
   * @param plainBlock a plaintext block of blockSize
   * @param cipherBlock the resulting ciphertext block of blockSize
   *
   * @return Whether the encryption was successful. Possible failure reasons
   *         include not calling init(). 
   */
  async command result_t BlockCipher.encrypt(CipherContext * context,
                                       uint8_t * block, uint8_t * cipherBlock)
    {
      register uint32_t l;
      register uint32_t r;
      register uint32_t *s = ((RC5Context*) context->context)->skey;
      uint8_t i, tmp;
      c2l(block, l);
      block += 4;
      c2l(block, r);
      l += *s++;
      r += *s++;
      for (i = RC5_ROUNDS; i > 0; i--) {
        l ^= r;   tmp = r; tmp &= 0x1f; rotl32(l, tmp);   l += *s++;
        r ^= l;   tmp = l; tmp &= 0x1f; rotl32(r, tmp);   r += *s++;
      }
      l2c(l, cipherBlock);
      cipherBlock += 4;
      l2c(r, cipherBlock);
      return SUCCESS;
    }

  /**
   * Decrypts a single block (of blockSize) using the key in the keySize. Not
   * all ciphers will implement this function (since providing encryption
   * is a useful primitive). 
   *
   * @param cipherBlock a ciphertext block of blockSize
   * @param plainBlock the resulting plaintext block of blockSize
   *
   * @return Whether the decryption was successful. Possible failure reasons
   *         include not calling init() or an unimplimented decrypt function.
   */
  async command result_t BlockCipher.decrypt(CipherContext * context,
                                       uint8_t * cipherBlock,
                                       uint8_t * plainBlock)
    {
      register uint32_t l;
      register uint32_t r;
      register uint32_t *s = ((RC5Context*) context->context)->skey +
        (2 * RC5_ROUNDS) + 1;
      uint8_t i, tmp;

      c2l(cipherBlock, l);
      cipherBlock += 4;
      c2l(cipherBlock, r);
      for (i = RC5_ROUNDS; i> 0; i--) {
        r -= *s--;   tmp = l;  tmp &= 0x1f; rotr32(r, tmp);   r ^= l;
        l -= *s--;   tmp = r;  tmp &= 0x1f; rotr32(l, tmp);   l ^= r;
      }
      r -= *s--;
      l -= *s;
      l2c(l, plainBlock);
      plainBlock += 4;
      l2c(r, plainBlock);
      return SUCCESS;
    }

  /**
   * Performs the key expansion on the real secret.
   *
   * @param secret key
   */
  result_t setupKey (CipherContext * context, uint8_t * key)
    {
      uint32_t *L,l,A,B,*S,k;
      uint8_t ii,jj, m;
      int8_t i;
      uint8_t tmp[8];
      S= ((RC5Context*)context->context)->skey;

      dumpBuffer ("RC5M:setupKey K", (uint8_t *)key, 8);      
      c2l(key,l);
      L = (uint32_t *) tmp;
      L[0]=l;
      key += 4;
      c2l(key,l);
      L[1]=l;
      S[0]=RC5_32_P;
      dumpBuffer ("RC5M:setupKey L", (uint8_t *)L, 8);      
      for (i=1; i< 2 * RC5_ROUNDS + 2; i++) {
        S[i] = (S[i-1] + RC5_32_Q);
        /*        sum =(*S+RC5_32_Q)&RC5_32_MASK;
                  S++;
                  *S = sum;
                  */
      }
      dumpBuffer ("RC5M: setupKey S", (uint8_t *)S, 2 * (RC5_ROUNDS +1) * 4);
      ii=jj=0;
      A=B=0;
      S= ((RC5Context*)context->context)->skey;
      for (i=3*(2*RC5_ROUNDS + 2) - 1; i>=0; i--) {
        k=(*S+A+B)&RC5_32_MASK;
        rotl32((k), (3));
        A=*S= k;
        S++;
        m=((char)(A+B)) & 0x1f;
        k=(*L+A+B)&RC5_32_MASK;
        rotl32((k), (m));
        B=*L= k;
        if (++ii >= 2*RC5_ROUNDS+2) {ii=0; S= ((RC5Context*)context->context)->skey; }
        jj ^= 4;
        L = (uint32_t *) (&tmp[jj]);
      }
      dumpBuffer ("RC5M: setupKey S",
                  (uint8_t*)((RC5Context*)context->context)->skey,
                  2 * (RC5_ROUNDS + 1) * 4);
      return SUCCESS;
    }

  /**
   * Returns the preferred block size that this cipher operates with. It is
   * always safe to call this function before the init() call has been made.
   *
   * @return the preferred block size for this cipher. In the case where the
   *         cipher operates with multiple block sizes, this will pick one
   *         particular size (deterministically).
   */
  async command uint8_t BlockCipherInfo.getPreferredBlockSize()
    {
      return BSIZE;
    }
    

}
