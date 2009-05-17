/*									tab:4
 *
 *
 * "Copyright (c) 2000-2002 The Regents of the University  of California.  
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
 * Authors: Naveen Sastry
 * Date:    9/26/02
 */

includes crypto;
interface BlockCipher
{
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
  command result_t init(CipherContext * context,
                        uint8_t blockSize, uint8_t keySize, uint8_t * key);

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
  command result_t encrypt(CipherContext * context,
                           uint8_t * plainBlock, uint8_t * cipherBlock);

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
  command result_t decrypt(CipherContext * context,
                           uint8_t * cipherBlock, uint8_t * plainBlock);

  
}

