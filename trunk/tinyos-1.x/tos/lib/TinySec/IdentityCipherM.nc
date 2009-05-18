// $Id: IdentityCipherM.nc,v 1.2 2003/10/07 21:46:22 idgay Exp $

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
 * @author Naveen Sastry
 */


module IdentityCipherM {
  provides interface BlockCipher;
  provides interface BlockCipherInfo;
}
implementation
{
  typedef struct IdentityCipherContext {
    uint8_t bsize;
  } IdentityCipherContext;
  
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
      ((IdentityCipherContext*)context->context)->bsize = blockSize;
      return SUCCESS;
    }

  /**
   * Encrypts a single block (of blockSize) using the key in the keySize.
   *
   * @param plainBlock a plaintext block of blockSize
   * @param cipherBlock the resulting ciphertext block of blockSize
   *
   * @return Whether the encryption was successful. Possible failure reasons
   *         include not calling init(). 
   */
  command result_t BlockCipher.encrypt(CipherContext * context,
                                       uint8_t * plainBlock,
                                       uint8_t * cipherBlock)
    {
      int8_t i = ((IdentityCipherContext*)context->context)->bsize - 1;
      while (i+1) {
        cipherBlock[i] = plainBlock[i];
        i--;
      }
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
  command result_t BlockCipher.decrypt(CipherContext * context,
                                       uint8_t * cipherBlock,
                                       uint8_t * plainBlock)
    {
      int8_t i = ((IdentityCipherContext*)context->context)->bsize - 1;
      while (i+1) {
        plainBlock[i] = cipherBlock[i];
        i--;
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
  command uint8_t BlockCipherInfo.getPreferredBlockSize()
    {
      return 8;
    }

}
