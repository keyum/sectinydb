// $Id: IdentityModeM.nc,v 1.2 2003/10/07 21:46:22 idgay Exp $

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
 * @author Naveen Sastry
 */
module IdentityModeM {
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
  typedef struct IdentityModeContext {
    uint8_t done;
  } __attribute__ ((packed)) IdentityModeContext;

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
      return SUCCESS;
    }

  /**
   * Encrypts numBlocks of plaintext blocks (each of size blockSize) using the
   * key from the init phase. The IV is a pointer to the initialization vector
   * (of size equal to the blockSize) which is used to initialize the
   * encryption.
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
      memcpy(cipherBlocks, plainBlocks, numBytes);
      return SUCCESS;
    }

  /**
   * Decrypts numBlocks of ciphertext blocks (each of size blockSize) using the
   * key from the init phase. The IV is a pointer to the initialization vector
   * (of size equal to the blockSize) which is used to initialize the
   * decryption.
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
      memcpy (plainBlock, cipherBlock, numBytes);
      return SUCCESS;
    }

  async command result_t BlockCipherMode.initIncrementalDecrypt (
						 CipherModeContext * context,
						 uint8_t * IV,
						 uint16_t length)
    {
      ((IdentityModeContext*)context)->done = 0;
      return SUCCESS;
    }

  async command result_t BlockCipherMode.incrementalDecrypt (
                                               CipherModeContext * context,
                                               uint8_t * cipher,
                                               uint8_t * plain,
                                               uint16_t length,
                                               uint16_t * done)
    {
      
      memcpy(plain + ((IdentityModeContext*)context)->done, cipher, length);
      *done = ((IdentityModeContext*)context)->done =
        ((IdentityModeContext*)context)->done + length;
      return SUCCESS;
    }
}
