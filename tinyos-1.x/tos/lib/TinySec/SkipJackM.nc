// $Id: SkipJackM.nc,v 1.3 2004/05/18 19:16:33 nksrules Exp $

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
 * Date:    12/28/02
 */

/**
 * @author Naveen Sastry
 */


includes crypto;

/**
 * From the NIST description of SkipJack.
 */
module SkipJackM {
  provides interface BlockCipher;
  provides interface BlockCipherInfo;
}
implementation
{
  // our context: we just expand the key to 20 bytes.
  //
  // we have two options for the expansion:
  //   1. no expansion. advantage: 10byte context. disadvantage: mucks up
  //      the G box code with ifs / mods. Alternatively adds lots of code and
  //      muckiness.
  //   2. expand key to 128 bytes. Makes G boxes easy to write, and minimal
  //      code expansion. disadvantage: wasted memory
  //   3. expand key to 20 bytes.  G boxes still simple, the encode and decode
  //      functions are a little more complicated, but still more or less
  //      managable. this is what we've implemented.
   typedef struct SJContext {
     uint8_t skey [ 20 ]; /* 2 times keysize.
                             makes unrolling keystream easier / efficient */
   } SJContext;

   // Skipjack only deals with 8 byte blocks
   enum { BSIZE = 8 };
   
   //   uint8_t SJ_F[] __attribute__((C)) = { // ram
   //   static const prog_uchar SJ_F[] = { // prog memory

   // F-BOX
   // It can live in either RAM (faster access) or program memory (save ram,
   // but slower access). The type CRYPTO_TABLE_TYPE, defined in crypto.h
   // defines where we drop the table and how we access it.  This is necessary
   // to compile for the PC target since it doesn't support tables in
   // program memory the same way.
   static const CRYPTO_TABLE_TYPE SJ_F[] = {
      0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4,
      0xB3, 0x21, 0x15, 0x78, 0x99, 0xB1, 0xAF, 0xF9,
      0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E,
      0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28,
      0x0A, 0xDF, 0x02, 0xA0, 0x17, 0xF1, 0x60, 0x68,
      0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53,
      0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19,
      0x7C, 0xAE, 0xE5, 0xF5, 0xF7, 0x16, 0x6A, 0xA2,
      0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B,
      0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8,
      0x55, 0xB9, 0xDA, 0x85, 0x3F, 0x41, 0xBF, 0xE0,
      0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90,
      0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69,
      0x45, 0x00, 0x94, 0x56, 0x6D, 0x98, 0x9B, 0x76,
      0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20,
      0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D,
      0x42, 0xED, 0x9E, 0x6E, 0x49, 0x3C, 0xCD, 0x43,
      0x27, 0xD2, 0x07, 0xD4, 0xDE, 0xC7, 0x67, 0x18,
      0x89, 0xCB, 0x30, 0x1F, 0x8D, 0xC6, 0x8F, 0xAA,
      0xC8, 0x74, 0xDC, 0xC9, 0x5D, 0x5C, 0x31, 0xA4,
      0x70, 0x88, 0x61, 0x2C, 0x9F, 0x0D, 0x2B, 0x87,
      0x50, 0x82, 0x54, 0x64, 0x26, 0x7D, 0x03, 0x40,
      0x34, 0x4B, 0x1C, 0x73, 0xD1, 0xC4, 0xFD, 0x3B,
      0xCC, 0xFB, 0x7F, 0xAB, 0xE6, 0x3E, 0x5B, 0xA5,
      0xAD, 0x04, 0x23, 0x9C, 0x14, 0x51, 0x22, 0xF0,
      0x29, 0x79, 0x71, 0x7E, 0xFF, 0x8C, 0x0E, 0xE2,
      0x0C, 0xEF, 0xBC, 0x72, 0x75, 0x6F, 0x37, 0xA1,
      0xEC, 0xD3, 0x8E, 0x62, 0x8B, 0x86, 0x10, 0xE8,
      0x08, 0x77, 0x11, 0xBE, 0x92, 0x4F, 0x24, 0xC5,
      0x32, 0x36, 0x9D, 0xCF, 0xF3, 0xA6, 0xBB, 0xAC,
      0x5E, 0x6C, 0xA9, 0x13, 0x57, 0x25, 0xB5, 0xE3,
      0xBD, 0xA8, 0x3A, 0x01, 0x05, 0x59, 0x2A, 0x46
   };

#define F(addr) CRYPTO_TABLE_ACCESS( &SJ_F[addr])
   
   // G-Permutation: 4 round feistal structure 
#define G(key, b, bLeft, bRight) \
     ( bLeft   = (b >> 8) ,          \
       bRight  = b,                  \
       bLeft  ^= F(bRight ^ key[0]), \
       bRight ^= F(bLeft  ^ key[1]), \
       bLeft  ^= F(bRight ^ key[2]), \
       bRight ^= F(bLeft  ^ key[3]), \
       (bLeft << 8) | bRight)

#define G_INV(key, b, bLeft, bRight) \
     ( bLeft   = (b >> 8),           \
       bRight  = b,                  \
       bRight ^= F(bLeft  ^ key[3]), \
       bLeft  ^= F(bRight ^ key[2]), \
       bRight ^= F(bLeft  ^ key[1]), \
       bLeft  ^= F(bRight ^ key[0]), \
       (bLeft << 8) | bRight)

   // A-RULE: 
#define RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight ) { \
    tmp = w4;                                \
    w4 = w3;                                 \
    w3 = w2;                                 \
    w2 = G(skey, w1, bLeft, bRight);         \
    w1 = tmp ^ w2 ^ counter;                 \
    counter++;                               \
    skey += 4; }

#define RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight) { \
    tmp = w4;                                \
    w4 = w1 ^ w2 ^ counter;                  \
    w1 = G_INV(skey, w2, bLeft, bRight);     \
    w2 = w3;                                 \
    w3 = tmp;                                \
    counter--;                               \
    skey -= 4; }                             \

   // B-RULE: 
#define RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight ) { \
    tmp = w1;                                \
    w1 = w4;                                 \
    w4 = w3;                                 \
    w3 = tmp ^ w2 ^ counter;                 \
    w2 = G(skey, tmp, bLeft, bRight);        \
    counter++;                               \
    skey += 4; }

#define RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight ) { \
    tmp = w1;                                \
    w1 = G_INV(skey, w2, bLeft, bRight);     \
    w2 = w1 ^ w3 ^ counter;                  \
    w3 = w4;                                 \
    w4 = tmp;                                \
    counter--;                               \
    skey -= 4; }

   
  result_t setupKey (CipherContext * context, uint8_t * key, uint8_t keysize);

  /**
   * Debug function
   */
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
   * Initialize the BlockCipher context.
   *
   * @param context structure to hold the opaque data from this initialization
   *        call. It should be passed to future invocations of this module
   *        which use this particular key.
   * @param blockSize size of the block in bytes. Some cipher implementation
   *        may support multiple block sizes, in which case any valid size
   *        is valid.
   * @param keySize key size in bytes
   * @param key pointer to the key
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
      return setupKey (context, key, keySize);
    }

  /**
   * Encrypts a single block (of blockSize) using the key in the keySize.
   *
   * @param context holds the module specific opaque data related to the
   *        key (perhaps key expansions). 
   * @param plainBlock a plaintext block of blockSize
   * @param cipherBlock the resulting ciphertext block of blockSize
   *
   * @return Whether the encryption was successful. Possible failure reasons
   *         include not calling init(). 
   */
  async command result_t BlockCipher.encrypt(CipherContext * context,
					     uint8_t * plainBlock,
					     uint8_t * cipherBlock)
  {
    // prologue 10 pushs = 20 cycles
    register uint8_t counter = 1;
    register uint8_t * skey  = ((SJContext*)context->context)->skey;
    register uint16_t w1, w2, w3, w4, tmp;
    register uint8_t bLeft, bRight;
    
    //dumpBuffer("SkipJack.encrypt: plainBlock", plainBlock, 8);
    
    c2sM(plainBlock, w1);
    plainBlock += 2;
    c2sM(plainBlock, w2);
    plainBlock += 2;
    c2sM(plainBlock, w3);
    plainBlock += 2;
    c2sM(plainBlock, w4);
    plainBlock += 2;

    /*
      // code if we had expanded key to 128 bytes. this is what the code below
      // does, but after every 5 operations, it resets the where we are
      // in the key back to the beginning of the skey. so our loops end up
      // looking a little funny.
      
      while (counter < 9) 
        RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
      while (counter < 17) 
        RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
      while (counter < 25) 
        RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
      while (counter < 33)
        RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
     */
    
    while (counter < 6)  // 5x
      RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey = ((SJContext*)context->context)->skey;
    while (counter < 9)  // 3x
      RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );

    while (counter < 11) // 2x
      RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey = ((SJContext*)context->context)->skey;
    while (counter < 16) // 5x
      RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey = ((SJContext*)context->context)->skey;
                         // 1x
    RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );

    while (counter < 21) // 4x
      RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey = ((SJContext*)context->context)->skey;
    while (counter < 25) // 4x
      RULE_A(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );

                         // 1x
    RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey = ((SJContext*)context->context)->skey;    
    while (counter < 31) // 5x
      RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );      
    skey = ((SJContext*)context->context)->skey;
    while (counter < 33) // 2x
      RULE_B(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    
    s2cM(w1, cipherBlock);
    cipherBlock += 2;
    s2cM(w2, cipherBlock);
    cipherBlock += 2;
    s2cM(w3, cipherBlock);
    cipherBlock += 2;
    s2cM(w4, cipherBlock);
    cipherBlock += 2;
    dumpBuffer ("SkipJack.encrypt: cipherBlock", cipherBlock - 8, 8);
    return SUCCESS;
  }

  /**
   * Decrypts a single block (of blockSize) using the key in the keySize. Not
   * all ciphers will implement this function (since providing encryption
   * is a useful primitive). 
   *
   * @param context holds the module specific opaque data related to the
   *        key (perhaps key expansions).    
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
    register uint8_t counter = 32;
    register uint8_t * skey  = ((SJContext*)context->context)->skey + 4;
    register uint16_t w1, w2, w3, w4, tmp;
    register uint8_t bLeft, bRight;
    
    dumpBuffer("SkipJack.decrypt: cipherBlock", plainBlock, 8);

    c2sM(cipherBlock, w1);
    cipherBlock += 2;
    c2sM(cipherBlock, w2);
    cipherBlock += 2;
    c2sM(cipherBlock, w3);
    cipherBlock += 2;
    c2sM(cipherBlock, w4);

    /*
      // code if we had expanded key to 128 bytes. this is what the code below
      // does, but after every 5 operations, it resets the where we are
      // in the key back to the beginning of the skey. so our loops end up
      // looking a little funny.
      
    while (counter > 24) 
      RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    while (counter > 16)
      RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    while (counter > 8)
      RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    while (counter > 0) 
      RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    */
      
    while (counter > 30) //2x
      RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey  = ((SJContext*)context->context)->skey + 16;
    while (counter > 25) //5x
      RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey  = ((SJContext*)context->context)->skey + 16;    
                         //1x
    RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    
    while (counter > 20) //4x
      RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey  = ((SJContext*)context->context)->skey + 16;
    while (counter > 16) //4x
      RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );

                         //1x
    RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey  = ((SJContext*)context->context)->skey + 16;    
    while (counter > 10) //5x
      RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey  = ((SJContext*)context->context)->skey + 16;
    while (counter > 8) // 2x
      RULE_B_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );

    while (counter > 5) // 3x
      RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    skey  = ((SJContext*)context->context)->skey + 16;    
    while (counter > 0) // 5x
      RULE_A_INV(skey, w1, w2, w3, w4, counter, tmp, bLeft, bRight );
    
    s2cM(w1, plainBlock);
    plainBlock += 2;
    s2cM(w2, plainBlock);
    plainBlock += 2;
    s2cM(w3, plainBlock);
    plainBlock += 2;
    s2cM(w4, plainBlock);

    dumpBuffer ("SkipJack.decrypt: plainBlock", plainBlock - 6, 8);
    return SUCCESS;
  }

  /**
   * Performs the key expansion on the real secret.
   *
   * @param secret key
   */
  result_t setupKey (CipherContext * context, uint8_t * key, uint8_t keysize)
  {
    int i = 0, m;
    uint8_t * skey = ((SJContext *)context->context)->skey;

    // for keys which are smaller than 80 bits, pad with 0 until they reach 80
    // bits in size.
    // note that key expansion is just concatenation. 
    for (; i < 20; i++) {
      m = i % 10;
      if ( m >= keysize)
        skey[i] = 0; 
      else 
        skey[i] = key[m];
    }
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
