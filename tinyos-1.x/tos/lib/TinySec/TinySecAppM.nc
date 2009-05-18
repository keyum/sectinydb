// $Id: TinySecAppM.nc,v 1.3 2003/11/30 07:07:15 nksrules Exp $

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
 * Date:    6/4/03
 */

/**
 * @author Naveen Sastry
 */


includes crypto;

module TinySecAppM {
  provides {
    interface TinySecApp;
  } uses {
    interface BlockCipherMode as mode;
  }
}

implementation
{


  
  // constants
  enum {BLOCK_SIZE = 8, TSA_KEYSIZE = 8 };

  // our context for encrypt / decrypt ops
  CipherModeContext context;
  // whether we've got an outstanding call in the mode
  bool busy;

  // whether the VI should be generated assuming that the key is being shared
  // by other nodes or not. if the key is being shared, then the local address
  // should be included in the iv
  bool gkey;
  // current iv
  uint8_t IVcnt[BLOCK_SIZE];  

  // arguments for the current task:
  uint8_t * plain;                  // plaintext buffer to use
  uint8_t * cipher;                 // ciphertext buffer to use
  uint8_t iv[BLOCK_SIZE];           // iv to use
  uint8_t numBytes;                 // number of bytes in operation.   

  
  /**
   * Initialize the component and its subcomponents.
   *
   * @return Whether initialization was successful.
   */
  command result_t TinySecApp.init(uint8_t *key, bool globalKey)
    {
      gkey = globalKey;
      busy = FALSE;
      memset(IVcnt, 0, BLOCK_SIZE);
      return call mode.init (&context, TSA_KEYSIZE, key);
    }

  /**
   * Fills in the iv buffer with ivlen of an IV while obeying the gkey
   * variable
   */
  void setIV(uint8_t ivlen)
    {
      /* ivlen |   iv format (TRUE == gkey)  | iv format (FALSE == gkey)
       * ------+-----------------------------+--------------------------
       *  8    |   xxxx xxAA                 |    xxxx xxxx
       *  7    |   xxxx xAA0                 |    xxxx xxx0
       *  6    |   xxxx AA00                 |    xxxx xx00
       *  5    |   xxxA A000                 |    xxxx x000
       *  4    |   xxAA 0000                 |    xxxx 0000
       *  3    |   xxA0 0000                 |    xxx0 0000
       *  2    |   xx00 0000                 |    xx00 0000
       *  1    |   x000 0000                 |    x000 0000
       *  0    |   0000 0000                 |    0000 0000
       *
       *           x - indicates byte comes from count
       *           A - indicates byte comes from TOS_LOCAL_ADDRESSS
       *           0 - the zero byte.
       */
      int i, j;
      memset (iv, 0, BLOCK_SIZE);
      if (!ivlen) return;
      
      // min (max (ivlen - 2, 0) + 2, ivlen);
      if (!gkey || ivlen <=2) {
        i = ivlen;
      } else if (ivlen >= 4) {
        i = ivlen -2;
      } else {// ivlen = 3;
        i = 2;
      }
      // set up the iv: first the x* counter portion:
      memcpy (iv, IVcnt, i);
      if (gkey) {
        if (ivlen > 3) {
          iv[i] = TOS_LOCAL_ADDRESS & 0xff;
          iv[i+1] = (TOS_LOCAL_ADDRESS >> 8) & 0xff;
        } else if (ivlen == 3) {
          iv[i] = TOS_LOCAL_ADDRESS & 0xff;
        }
      }
      // incrmenet iv cnt
      IVcnt[0]++;
      i--;
      for (j = 0; j < i; j++) {
        if (IVcnt[j]) break;
        IVcnt[j+1]++;
      }
    }

  // task to actually run the encryption
  task void encrypt()
    {
      result_t res = call mode.encrypt (&context, plain, cipher, numBytes, iv);
      busy = FALSE;
      signal TinySecApp.encryptDataDone(res, cipher);
    }

  result_t command TinySecApp.encryptData (uint8_t * plaintext,
                                           uint8_t plainLength, 
                                           uint8_t IVlength,
                                           uint8_t * IV,
                                           uint8_t * ciphertext)    {
      if (busy || IVlength > BLOCK_SIZE) {
        return FAIL;
      }
      busy = TRUE;
      plain = plaintext;
      cipher = ciphertext;
      numBytes = plainLength;
      // generate an iv and give a copy back to the caller;
      setIV (IVlength);
      memcpy (IV, iv, IVlength);
      
      if (! post encrypt()) {
        busy = FALSE;
        return FAIL;
      }
      return SUCCESS;      
    }

  // task to actually run the decryption  
  task void decrypt()
    {
      //int a;
      //result_t res = call mode.initIncrementalDecrypt (&context, 
      //                                                 iv, numBytes);
      //res = call mode.incrementalDecrypt (&context, cipher, plain, numBytes,
      //                                    &a);
      result_t res = call mode.decrypt (&context, cipher, plain, numBytes, iv);
      busy = FALSE;
      signal TinySecApp.decryptDataDone(res, plain);
    }

  result_t command TinySecApp.decryptData (uint8_t * ciphertext,
                                uint8_t cipherLength, 
                                uint8_t IVlength,
                                uint8_t * IV,
                                uint8_t * plaintext)
    {
      if (busy || IVlength > BLOCK_SIZE) {
        return FALSE;
      }
      busy = TRUE;
      plain = plaintext;
      cipher = ciphertext;
      numBytes = cipherLength;

      //only use relevent portion of IV
      memcpy (iv, IV, IVlength);
      memset (iv + IVlength, 0, 8 - IVlength);
      if (! post decrypt()) {
        busy = FALSE;
        return FAIL;
      }
      return SUCCESS;
    }

}
