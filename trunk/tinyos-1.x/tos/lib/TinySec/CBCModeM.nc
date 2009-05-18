// $Id: CBCModeM.nc,v 1.2 2003/10/07 21:46:22 idgay Exp $

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
 * Date:    9/26/02
 */

/**
 * Implements CBC Mode using Cipher Text Stealing (CBC-CTS) as described in
 * Schneir's Applied Cryptography (195-6) and RFC-2040.
 * <br>
 * Plain CBC mode is pretty simple; using CTS complicates things. CTS allows
 * the ciphertext to be the same size as the plaintext, even for plaintexts
 * which aren't a multiple of the block size.
 *
 *        C_0     == E[IV]
 *        C_i     == E[ C_{i-1} ^ P_i ]                   0 < i < n-2
 *        C_{n-1} == E[ C_{n-2} ^ P_{n-1} ]
 *                == E[ C_{n-2} ^ (P_{n-1} || 0/-L) ]
 *                == C_{n-1}/+L || C_{n-1}/-L    (naming of ciphertext block
 *                                                into left and right pieces)
 *        C_n     == E[ C_{n-1}/+L ^ P_n || C_{n-1}/-L ]
 *
 *  Where 0 = the zero block
 *        n = number of blocks. the last block may be length 1..blockSize bytes
 *        L = |P_n|, the length of the last block and
 *        /+L refers to the first L bytes of a block and
 *        /-L refers to the last (blockSize - L) bytes of a block
 *
 * We then output C_0 || ... || C_{n-2} || C_n || C_{n-1}/+L so that the
 * ciphertext is the same size as the input.
 * @author Naveen Sastry
 */
module CBCModeM {
  provides {
    interface BlockCipherMode;
  }
  uses {
    interface BlockCipher;
    interface BlockCipherInfo;
  }
} 

implementation
{
  enum {
    // we allocate some static buffeers on the stack; they have to be less
    // than this size
    CBCMODE_MAX_BLOCK_SIZE = 8
  };

  // We run a simple state machine in the incremental decrypt:
  //
  //    +--> ONE_BLOCK
  //    |
  // ---|
  //    |
  //    +--> GENERAL --+---> TWO_LEFT_A ----> TWO_LEFT_B
  //            ^      |
  //            |      |
  //            +------+
  enum {
    ONE_BLOCK,
    GENERAL,
    TWO_LEFT_A,
    TWO_LEFT_B
  };
  
  typedef struct CBCModeContext {
    uint8_t spill1 [CBCMODE_MAX_BLOCK_SIZE ];
    uint8_t spill2 [CBCMODE_MAX_BLOCK_SIZE ];
    uint8_t bsize;
    uint16_t remaining; // how many more bytes of ciphertext do we need to recv
    uint16_t completed; // how many bytes of plaintext we've deciphered.
    uint8_t accum;      // TRUE iff spill1 is the accumulator & spill2 holds
                        // prev cipher text. false o.w.
    uint8_t offset;     // into the accumulator
    uint8_t state;      // state enum
  } __attribute__ ((packed)) CBCModeContext;

#define MIN(a, b) ( ((a) < (b)) ? (a) : (b))
  
  /**
   * Initialize the Mode.  It uses the underlying BlockCipher's
   * preferred block cipher mode, and passes the key and keySize parameters
   * to the underlying BlockCipher.
   *
   * @param context structure to hold the opaque data from this initialization
   *        call. It should be passed to future invocations of this module
   *        which use this particular key. It also contains the opaque
   *        context for the underlying BlockCipher as well.
   * @param keySize key size in bytes
   * @param key pointer to the key
   * @return Whether initialization was successful. The command may be
   *         unsuccessful if the key size is not valid for the given cipher
   *         implementation. It can also fail if the preferred block size of
   *         the cipher does not agree with the preferred size of the mode.
   */
  command result_t BlockCipherMode.init(CipherModeContext * context,
                                        uint8_t keySize, uint8_t * key)
    {
      uint8_t blockSize = call BlockCipherInfo.getPreferredBlockSize();
      if (blockSize > CBCMODE_MAX_BLOCK_SIZE) {
        return FAIL;
      }

      ((CBCModeContext*)context->context)->bsize = blockSize;
      return call BlockCipher.init (&context->cc, blockSize, keySize, key);
    }

  void dumpBuffer (char * bufName, uint8_t * buf, uint8_t size)
    {
#ifdef O
      uint8_t i = 0;
      // fixme watch buffer overrun
      char tmp[256];
      for (; i < size; i++) {
        sprintf (tmp + i * 3, "%2x ", (char)buf[i] & 0xff);
      }
      dbg(DBG_CRYPTO, "%s: {%s}\n", bufName, tmp);
#endif
    }

  /**
   * Encrypts numBlocks of plaintext blocks (each of size blockSize) using the
   * key from the init phase. The IV is a pointer to the initialization vector
   * (of size equal to the blockSize) which is used to initialize the
   * encryption.
   *
   * In place encryption should work provided that the plain and and cipher
   * buffer are the same. (they may either be the same or
   * non-overlapping. partial overlaps are not supported).
   *
   * @param plainBlocks a plaintext block numBlocks, where each block is of
   *        blockSize bytes
   * @param cipherBlocks an array of numBlocks * blockSize bytes to hold
   *        the resulting cyphertext
   * @param numBlocks number of data blocks to encrypt
   * @param IV an array of the initialization vector. It should be of
   *        blockSize bytes
   * @return Whether the encryption was successful. Possible failure reasons
   *        include not calling init(). 
   */
  async command result_t BlockCipherMode.encrypt(CipherModeContext * context,
						 uint8_t * plainBlocks,
						 uint8_t * cipherBlocks,
						 uint16_t numBytes, uint8_t * IV)
    {
      uint8_t i,j, t, bsize, bsize2;
      uint16_t bc = 0;
      uint8_t spillblock[CBCMODE_MAX_BLOCK_SIZE];
      uint8_t eIV[CBCMODE_MAX_BLOCK_SIZE];

      bsize = ((CBCModeContext*) (context->context))->bsize;
      bsize2 = bsize + bsize;
      if (numBytes == 0) {
        return SUCCESS;
      }
      // we can only encrypt 256 blocks (since our block counter is a byte
      // [quicker to maintain an 8 bit counter than a 16 bit counter]_
      if ((numBytes / 256) > bsize) {
        return FAIL;
      }
      // we need at least 1 block size to work with.
      if (numBytes < bsize) {
        return FAIL;
      }
      dumpBuffer ("CBC.encrypt orig", plainBlocks, numBytes);

      if (call BlockCipher.encrypt (&(context->cc), IV, eIV) == FAIL) {
        return FAIL;
      }
      IV = eIV;
      
      // special case for the 1 byte encryption
      if (numBytes == bsize) {
        // FIXME UNROLL:
        // xor the iv and plaintext and encrypt
        for (j = 0; j < bsize; j++) {
          cipherBlocks[bc+ j] = plainBlocks[bc+j] ^ IV[j];
        }
        if (call BlockCipher.encrypt (&(context->cc), cipherBlocks + bc,
                                      cipherBlocks + bc) == FAIL) {
          return FAIL;
        }
        return SUCCESS;
      }

      // this loop deals with all but the last two blocks 
      // it xors the prev encr (stored in iv) and encrypts
      if (numBytes > bsize2) {       
        for (bc = 0; bc < numBytes - bsize2; bc += bsize) {
          // FIXME UNROLL:
          for (j = 0; j < bsize; j++) {
            cipherBlocks[bc+ j] = plainBlocks[bc+j] ^ IV[j];
          }
          if (call BlockCipher.encrypt (&context->cc, cipherBlocks + bc,
                                        cipherBlocks + bc) == FAIL) {
            return FAIL;
          }
          IV = cipherBlocks + bc;
        }
      }
      
      dbg (DBG_CRYPTO, "bc: %d\n", bc);
      // Now we deal with the last two blocks. The very last block may not be
      // full, so we use a technique called ciphertext stealing to deal with
      // it.
      //
      // We encrypt the second to last block as normal. Call the ciphertext
      // C_{n-1}. We do not output this ciphertext.  We then xor the last
      // partial block with C_{n-1} (of size m) and encrypt it to obtain
      // C_n. The ciphertext C_n is output in place of C_{n-1}. And we then
      // only need to output the first m bytes of C_{n-1}.
      //
      // How does this work? Well to decrypt, it is easy to obtain
      // C_{n-1} ^ p_n (the decryption of C_{n-1} yields this). xoring the
      // first m bytes of C_{n-1} yields p_n, and hence the complete C_{n-1}. 

      // start by generating C_{n-1} -- xor with the prev IV and encrypt.
      for (j = 0; j < bsize; j++) {
        spillblock[j] = plainBlocks[bc+ j] ^ IV[j];
      }
      if (call BlockCipher.encrypt(&context->cc, spillblock, spillblock) ==
          FAIL) {
          return FAIL;
      }
      dumpBuffer ("CBC.encrypt spill:", spillblock, bsize);
      
      j = numBytes - bc - bsize;
      dbg(DBG_CRYPTO, "CBC.encrypt j: %d; bc: %d\n", j, bc);

      // xor and output the first m bytes of C_{n-1}
      for (i = 0 ; i < j; i++) {
        // we do this in a convoluted manner to avoid alias problmes:
        //       if cipherBlock = plainblock
        t = plainBlocks[bc + bsize + i];
        cipherBlocks[bc + bsize +i] = spillblock[i];
        spillblock[i] ^= t;
      }
      // and encrypt -- note that the output of the encryption places the last
      // ciphertext in the correct position -- where the C_{n-1} would
      // ordinarily go. 
      if (call BlockCipher.encrypt(&context->cc, spillblock,
                                   cipherBlocks + bc) == FAIL) {
        return FAIL;
      }
      dumpBuffer( "CBC.encrypt cipher:", cipherBlocks, numBytes);
      return SUCCESS;
    }

  /**
   * Decrypts numBlocks of ciphertext blocks (each of size blockSize) using the
   * key from the init phase. The IV is a pointer to the initialization vector
   * (of size equal to the blockSize) which is used to initialize the
   * decryption.
   *
   * In place decryption should work provided that the plain and and cipher
   * buffer are the same. (they may either be the same or
   * non-overlapping. partial overlaps are not supported).
   *
   * @param cipherBlocks an array of numBlocks * blockSize bytes that holds
   *        the cipher text
   * @param plainBlocks an array of numBlocks * blockSize bytes to hold the
   *        resulting plaintext.
   * @param numBlocks number of data blocks to encrypt
   * @param IV an array of the initialization vector. It should be of
   *        blockSize bytes
   * @return Whether the decryption was successful. Possible failure reasons
   *        include not calling init(). 
   */
  async command result_t BlockCipherMode.decrypt(CipherModeContext * context,
						 uint8_t * cipherBlock,
						 uint8_t * plainBlock,
						 uint16_t numBytes, uint8_t * IV)
    {
      uint8_t i = 0, partialSize = 0,
        bsize = ((CBCModeContext*)context->context)->bsize;
      uint16_t bc = 0;
      uint8_t spillblock[CBCMODE_MAX_BLOCK_SIZE];
      uint8_t spillblock2[CBCMODE_MAX_BLOCK_SIZE];
      uint8_t eIV[CBCMODE_MAX_BLOCK_SIZE];
      
      if (numBytes == 0) {
        return SUCCESS;
      }
      // we need at least one block size to deal with.
      if (numBytes < bsize) {
        return FAIL;
      }

      if (call BlockCipher.encrypt (&context->cc, IV, eIV) != SUCCESS) {
        return FAIL;
      }
      IV = eIV;
      
      // deal with the single block case a bit specially: encrypt and xor it
      // and move on.
      if (numBytes == bsize) {
        if (call BlockCipher.decrypt (&context->cc,
                                      cipherBlock, plainBlock) != SUCCESS) {
          return FAIL;
        }
        for (i = 0; i < bsize; i++ ) {
          plainBlock[i] ^= IV[i];
        }
        return SUCCESS;
      }
      
      // else we know there are 2 or more blocks (though the last one may be a
      // partial).

      dumpBuffer( "CBC.decrypt cipher:", cipherBlock, numBytes);
      
      // find the start of the last whole block:
      bc = bsize;
      while (bc  < numBytes) bc += bsize;
      // and the block before it
      bc -= (bsize << 1);
      partialSize = numBytes - bc - bsize;
      
      dbg (DBG_CRYPTO, "CBC.decrypt bc: %d; partial %d \n", bc, partialSize);
      // split up the computation: depending on whether  the last block
      // is full or not. 
      if (partialSize) {
        // decrypt C_n
        if (call BlockCipher.decrypt (&context->cc, cipherBlock + bc,
                                      spillblock) != SUCCESS) {
          return FAIL;
        }
        // recover C_{n-1}, [in spillblock2] and P_{n} [in spillblock]
        for (i = 0; i < partialSize; i++) {
          // bit convoluted for the case where we
          // alias plainBlock and CipherBlock
          spillblock[i] ^= cipherBlock [bc + bsize + i];
          spillblock2[i] = cipherBlock[bc + bsize + i];
          plainBlock[bc + bsize + i] = spillblock[i];
        }
        // copy over the remaining portion of the spillblock
        for (i = partialSize; i < bsize; i++) {
          spillblock2[i] = spillblock[i];
        }
        // and decrypt the spillblock (C_{n-1}) into position.
        if (call BlockCipher.decrypt (&context->cc, spillblock2,
                                      plainBlock + bc) != SUCCESS) {
          return FAIL;
        }
        // NOW xor pref [iv or prev block]. We work from the end forward.
        // that happens after the if / else
        dumpBuffer ("CBC.decrypt partial", plainBlock, numBytes);
      } else {
        // bit simpler - just decrypt C_{n-1} into the spillblock
        if (call BlockCipher.decrypt (&context->cc, cipherBlock + bc,
                                      spillblock) != SUCCESS) {
          return FAIL;
        }
        // xor to recover C_{n} and decrypt into place
        for (i = 0; i < bsize; i++) {
          spillblock[i] ^= cipherBlock[bc + i + bsize];
        }
        if (call BlockCipher.decrypt (&context->cc, cipherBlock + bc + bsize,
                                      plainBlock + bc) != SUCCESS) {
          return FAIL;
        }
        // copy P_{n-1} into place
        for (i = 0; i < bsize; i++) {
          plainBlock[bc + bsize + i] = spillblock[i];
        }
        // NOW xor prev [iv or prev block in]
      }
      // handle blocks 0.. n-2
      // by xoring in the n-1 ciphertext and decrypting.
      while (bc) {
        bc -= bsize;
        for (i = 0 ; i < bsize; i++) {
          plainBlock [ bc + bsize + i] ^= cipherBlock [bc + i];
        }
        if (call BlockCipher.decrypt (&context->cc, cipherBlock + bc,
                                      plainBlock + bc) != SUCCESS) {
          return FAIL;
        }
      }
      // xor the iv to recover P_0
      for (i = 0 ; i < bsize; i++) {
        plainBlock[i] ^= IV[i];
      }
      dumpBuffer( "CBC.decrypt cipher:", plainBlock, numBytes);      
      return SUCCESS;
    }

  /**
   * Initializes the mode for an incremental decryption operation. This step
   * is necessary for incremental decryption where the incoming data stream is
   * processed a byte at a time and cipher operations are done as soon as
   * possible. This is meant to allow for better overlapping of decryption
   * with a slower process that receives the encrypted stream (say via the
   * network ).
   *
   * This call may induce a block cipher call.
   
   * @param context holds the module specific opaque data related to the
   *        key (perhaps key expansions) and other internal state.
   * @param IV The initialization vector that was used to encrypt this
   *        particular data stream. This array must have a length equal to
   *        one block size.
   * @param The exact length of the data stream in bytes; this must be at
   *        least the underlying block cipher size.
   * @return Whether the initialization was successful. Possible failure
   *        reasons include not calling init() or an underlying failure in the
   *        block cipher.
   */
  async command result_t BlockCipherMode.initIncrementalDecrypt (
						 CipherModeContext * context,
						 uint8_t * IV,
						 uint16_t length)
    {
      CBCModeContext * mcontext = (CBCModeContext*)(context->context);
      if (!length) return SUCCESS;
      if ( length < mcontext->bsize) return FAIL;
      
      mcontext->remaining = length;
      // decrypt the IV. 
      if (call BlockCipher.encrypt (&context->cc, IV, mcontext->spill1) !=
                                    SUCCESS) {
        return FAIL;
      }
      dumpBuffer ("E(IV)", mcontext->spill1, 8);
      // prime the pump:
      mcontext->offset = mcontext->completed = 0; // done amt
      mcontext->accum = FALSE;
      // figure out our state based on the amount of ciphertext that we're
      // gonna get:
      if (length == mcontext->bsize) {
        mcontext->state = ONE_BLOCK;
      } else if (length <= mcontext->bsize * 2) {
        mcontext->state = TWO_LEFT_A;
      } else {
        mcontext->state = GENERAL;
      }
      return SUCCESS;
    }

  /**
   * Performs an incremental decryption operation. It executes roughly one
   * block cipher call for every block's worth of ciphertext provided, placing
   * the result into the plaintext buffer. The done out parameter gives an
   * indication of the amount of data that has been successfully been
   * decrypted.
   *
   * @param context holds the module specific opaque data related to the
   *        key (perhaps key expansions) and other internal state.
   * @param ciphertext Pointer to the start of the next ciphertext buffer.
   * @param plaintext Pointer to the start of the buffer which is large enough
   *        to hold the entire ciphertext. This buffer must be passed in every
   *        time to the incrementalDecrypt function.  After this call,
   *        <i>done</i> bytes of the plaintext buffer will be available for
   *        consumption. 
   * @param length The number of bytes that is being provided in the ciphertext
   * @param done A pointer to an int which will be filled in after the call
   *        completes with the number of bytes of plaintext which is
   *        available. 
   * @return Whether the call was successful or not. Possible failure reasons
   *        include not calling init(), an underlying failure in the block
   *        cipher, or providing more ciphertext than is expected.
   */
  async command result_t BlockCipherMode.incrementalDecrypt (
					       CipherModeContext * context,
                                               uint8_t * cipher,
                                               uint8_t * plain,
                                               uint16_t length,
                                               uint16_t * done)
    {
      CBCModeContext * mcontext = (CBCModeContext*)(context->context);
      int i, j;
      uint8_t * accum ;
      uint8_t * lastCipher ;
      uint8_t bsize = mcontext->bsize;
      uint16_t completed = mcontext->completed;

      // We run this deal as a simple state machine. See above for a diagram
      // of states and their transitions.


      // first, start with some simple checking:
      dbg(DBG_CRYPTO, "CBCModeM:incrementalDecrypt: <entry>length %d\n",
          length);
      if (!length) { *done = mcontext->completed; return SUCCESS; }
      if (length > mcontext->remaining) {
        dbg(DBG_CRYPTO,"Fail 1\n"); return FAIL; }

      while (length) {
        // determine which is the accumulator and which contains the previous
        // ciphertext. the accumulator is our temp storage space for the
        // current ciphertext. once it gets full, we decrypt it.
        if (mcontext->accum) {
          accum = mcontext->spill1;
          lastCipher = mcontext->spill2;
        } else {
          accum = mcontext->spill2;
          lastCipher = mcontext->spill1;        
        }

        // all but the TWO_LEFT_B state can use this common code to populate
        // the accumulator witht he code from the ciphertext.
        if (mcontext->state != TWO_LEFT_B) {
          if (mcontext->offset + length < bsize) {
            // this means we haven't filled up a block. so we copy into the
            // accumulator, and update a few counters and ext.
            dbg(DBG_CRYPTO, "incrementalDecrypt: Moved %d; 0 left this run\n",
                length);  
            memcpy(accum + mcontext->offset, cipher, length);
            *done = mcontext->completed = completed;
            mcontext->offset += length;
            mcontext->remaining -= length;
            return SUCCESS;
          }
          // we can fill up a block's worth of data. so do so, update some
          // state, and move on down to the appropriate state below.
          j = bsize - mcontext->offset ;
          memcpy(accum + mcontext->offset, cipher, j);
             
          dbg(DBG_CRYPTO, "incrementalDecrypt: Moved %d bytes; "
                          "%d remaining this run\n", j, length - j); 
          mcontext->remaining -= j;
          cipher += j;
          length -= j;
          mcontext->offset = 0;
        }

        // reaching this block indicates we have filled up the accumulator.

        if (mcontext->state == ONE_BLOCK) {
          // decrypt the one block:
          dbg(DBG_CRYPTO, "CBCModeM: incrementalDecrypt. State ONE_BLOCK\n");
          if (call BlockCipher.decrypt (&context->cc, accum,
                                        plain) != SUCCESS) {
            return FAIL;
          }
          // and xor with E(IV), which is stored in lastCipher.
          for (i = 0; i < bsize; i++) {
            plain[i] ^= lastCipher[i];
          }
          dumpBuffer ("plain", plain, 8);
          // and fill in some stats and exit.
          *done = mcontext->completed = bsize;
          return SUCCESS;
        }

        if (mcontext->state == GENERAL) {
          // we're in block i, where 0 <= i <= n-2
          dbg(DBG_CRYPTO, "CBCModeM: incrementalDecrypt. State GENERAL\n");
          // decrypt
          if (call BlockCipher.decrypt (&context->cc, accum,
                                        plain + completed) != SUCCESS) {
	    dbg(DBG_CRYPTO,"Fail 3\n");
            return FAIL;
          }
          // xor with the prev ciphertext
          for (i = 0; i < bsize; i++) {
            plain[i + completed] ^= lastCipher[i];
          }
          // update state:
          completed += bsize;
          mcontext->accum = !mcontext->accum;
          // transition if there are only 2 blocks to go.
          if (mcontext->remaining <= bsize * 2) {
            mcontext->state = TWO_LEFT_A;
            continue;
          }
        }

        if (mcontext->state == TWO_LEFT_A) {
          // two blocks to go, one after this stage completes.
          // we have now accumulated C_n
          dbg(DBG_CRYPTO, "CBCModeM: incrementalDecrypt. State 2LEFTA\n");
          // decrypt. note we decrypt INTO the accumulator, which now holds
          // C_{n-1}/+L ^ P_n || C_{n-1}/-L
          // we need to wait to receive C_{n-1}/+L to recover P_n as well
          // as C_{n-1}, which we'll then use to recover P_{n-1}
          if (call BlockCipher.decrypt (&context->cc, accum, accum) !=
                                                                     SUCCESS) {
	    dbg(DBG_CRYPTO,"Fail 4\n");
	    return FAIL;
          }
          // transition state:
          mcontext->state = TWO_LEFT_B;
          dbg(DBG_CRYPTO, "DBCModeM: ** Switched to state 2LEFTB "
              "with %d remaining\n", mcontext->remaining);
          continue;
        }

        if (mcontext->state == TWO_LEFT_B) {
          // last block. this can't use the accum population code from
          // above since it's a bit convoluted. recall from TWO_LEFT_A, that
          // accum contains C_{n-1}/+L ^ P_n || C_{n-1}/-L
          // cipher contains C_{n-1}+L
          //
          dbg(DBG_CRYPTO, "CBCModeM: incrementalDecrypt. State 2LEFTB\n");
          j = mcontext->offset + length; // stop pos
          // iterate over each block of cipher
          for (i = mcontext->offset; i < j; i++) {
            dbg(DBG_CRYPTO, "incrementalDecrypt:  %d %d\n", i, j);
            // recover P_n
            plain[completed + bsize + i] =
              accum[i] ^ cipher[i-mcontext->offset];
            // and set up accum to be C_{n-1}
            accum[i] = cipher[i-mcontext->offset];
          }
          mcontext->remaining -= length;
          if (mcontext->remaining) {
            mcontext->offset += length;
            length =0;
          } else {
            // if we've received all of C_{n-1}, decrypt it, which is
            // P_{n-1} ^ C_{n-2}; C{n-2} conveniently lives in lastCipher,
            // so we can xor to recover.
            if (call BlockCipher.decrypt (&context->cc, accum,
                                     plain + completed) != SUCCESS) {
	      dbg(DBG_CRYPTO,"Fail 5\n");
	      return FAIL;
            }
            for (i = 0; i < bsize; i++) {
              plain[i + completed] ^= lastCipher[i];
            }
            // set some state.
            mcontext->remaining = 0;
            mcontext->completed +=
              bsize + length + mcontext->offset; 
            *done = mcontext->completed;
            return SUCCESS;
          }
        }
      }
      // and voilla! we're done.
      *done = mcontext->completed = completed;
      return SUCCESS;
    }
}
