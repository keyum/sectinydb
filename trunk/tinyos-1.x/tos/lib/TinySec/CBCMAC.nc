// $Id: CBCMAC.nc,v 1.2 2003/10/07 21:46:22 idgay Exp $

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
 * Date:    
 */

/**
 * @author Naveen Sastry
 */

module CBCMAC {
  provides {
    interface MAC;}
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
    CBCMAC_BLOCK_SIZE = 8
  };
  typedef struct CBCMACContext {
    // the result of our partial computation. we xor this with new data and
    // then encrypt it when full.
    uint8_t  partial[CBCMAC_BLOCK_SIZE];
    // the total number of bytes left for the MAC to process.
    uint16_t length;
    // the current offset into the partial array. 
    uint8_t  blockPos;
  } __attribute__ ((packed)) CBCMACContext;
  
  /**
   * Initializes the MAC layer and stores any local state into the context
   * variable. The context variable should be used for future invocations
   * which share this key. It uses the preferred block size of the underlying
   * BlockCipher
   *
   * @param context opaque data structure to hold the module specific state
   *        associated with this key.
   * @param keySize length of the key in bytes.
   * @param key pointer to a buffer containing keySize bytes of shared key data
   * @return Whether initialization was successful. The command may be
   *         unsuccessful if the key size or blockSize are not valid for the
   *         given cipher implementation. 
   */
  command result_t MAC.init (MACContext * context, uint8_t keySize,
                             uint8_t * key)
    {
      if ( call BlockCipherInfo.getPreferredBlockSize() != CBCMAC_BLOCK_SIZE) {
        // the block cipher exceeds our max size.
        return FAIL;
      }
      // just init the underlying block cipher
      return call BlockCipher.init (&context->cc, CBCMAC_BLOCK_SIZE,
                                    keySize, key);
    }
  
  /**
   * Initializes an invocation of an incremental MAC computation. This is
   * provided for asynchronous operation so that the MAC may be incrementally
   * computed. Partial state is stored in the context.
   *
   * @param context opaque data structure to hold the module specific state
   *        associated with this invocation of the incremental computation.
   * @param length the total length of data that is forthcoming
   * @return whether the incremental initialization was successful. This can
   *        fail if the underlying cipher operation fails.
   */
  async command result_t MAC.initIncrementalMAC (MACContext * context,
						 uint16_t length)
    {
      // temp. plain text. to make CBC-Mac secure for variable length messages
      // we need to modify the normal CBC procedure: namely, we initialze the
      // mac by encrypting the 0th block as the length (in blocks) of the
      // message. This results in a secure MAC.
      //
      // see Mihir Bellare, Joe Kilian, Phillip Rogaway
      // The Security of the Cipher Block Chaining Message Authentication Code
      // 1995, p12-13

      // temp buffer to hold length buffer which we'll encrypt to the
      // real "partial" stored in the context. 
      uint8_t partial[CBCMAC_BLOCK_SIZE];
      // length divided by 8 [ ie num blocks]
      uint8_t numBlocks = length >> 3;
      memset (partial, 0, 6);
      partial[6] = (numBlocks >> 8) & 0xff;
      partial[7] = (numBlocks & 0xff);

      ((CBCMACContext*) context->context)->length = length;
      ((CBCMACContext*) context->context)->blockPos = 0;
      return call BlockCipher.encrypt (&context->cc, partial,
                                       ((CBCMACContext*) context->context)->partial);
    }
  
  /**
   * Computes an incremental MAC on msgLen bytes of the msg. This call is
   * tied to the initIncrementalMAC call, which must be made first. This call
   * can fail if the msgLen provided exceeds the amount specified earlier or
   * if a block cipher operation fails.
   *
   * @param context opaque data structure to hold the module specific state
   *        associated with this invocation of the incremental computation.
   * @param msg the message data to add to the incremental computation.
   * @param msgLen number of bytes to add for the incremental computation.
   * @return whether the incremental mac computation succeeded or not. It can
   *        fail if more data is provided than the initial initialization
   *        indicated or if the underlying block cipher fails.
   */
  async command result_t MAC.incrementalMAC (MACContext * context, uint8_t * msg, 
					     uint16_t msgLen)
    {
      uint16_t i, pos = ((CBCMACContext*) context->context)->blockPos;
      uint8_t * partial = ((CBCMACContext*) context->context)->partial;

      dbg(DBG_USR1, "MAC.MAC.incrementalMAC \n");
      // only proceed if the we're expecting less than msgLen of data. 
      if ( ((CBCMACContext*) context->context)->length < msgLen) {
        return FAIL;
      }
      // simple here: just xor the msg with the partial and when we fill up
      // the partial, encrypt it.
        dbg(DBG_USR1, "incrementalMAC msgLen: %d\n",msgLen);
      for (i = 0; i < msgLen; i++) {
        // unroll
        dbg(DBG_USR1, "incrementalMAC i: %d\n",i);
        partial[pos++] ^= msg[i];
        if (pos == 7) {
          if (!call BlockCipher.encrypt (&context->cc, partial, partial)) {
            return FAIL;
          }
          pos = 0;
        }
      }
      
      ((CBCMACContext*) context->context)->length -= msgLen;
      ((CBCMACContext*) context->context)->blockPos = pos;
      dbg(DBG_USR1, "Leaving MAC.MAC.incrementalMAC \n");
      return SUCCESS;
    }
    
  /**
   * Returns the actual MAC code from an in-progress incremental MAC
   * computation. The initIncrementalMAC and length bytes of data must have
   * been computed using the provided context for this function to succeed.
   * This function may fail if the requested MAC size exceeds the underlying
   * cipher block size, or if the incremental MAC computation has not yet
   * finished.
   *
   * @param context opaque data structure to hold the module specific state
   *        associated with this invocation of the incremental computation.
   * @param MAC resulting buffer of at least macSize to hold the generated MAC
   * @param macSize the number of bytes of MAC to generate. This must be
   *        less than or equal to the underlying blockCipher block size.
   * @return whether the command succeeded or not. It can fail if the
   *        underlying block cipher fails or if not all expected data was
   *        received from the initialization function
   */
  async command result_t MAC.getIncrementalMAC (MACContext * context, uint8_t * res,
						uint8_t macSize)
    {
      uint8_t blockPos = ((CBCMACContext*) context->context)->blockPos;
      uint8_t * partial = ((CBCMACContext*) context->context)->partial;
      // make sure they're asking for a valid mac size and that we've received
      // all the data that we're expecting.
      if (! macSize || macSize > 8 ||
          ((CBCMACContext*) context->context)->length) {
	dbg(DBG_CRYPTO,"MAC getIncrementalMAC failure: length left %d.\n",
	    ((CBCMACContext*) context->context)->length);
        return FAIL;
      }
      // the last block may be a partial block [ie, may have some data that
      // has been xored but not yet encrypted]. if so, encrypt it.
      if (blockPos) {
        // one last encr: xor with 10000 
        partial[++blockPos] ^= 1;
        if (! call BlockCipher.encrypt (&context->cc, partial, partial)) {
          return FAIL;
        }
        ((CBCMACContext*) context->context)->blockPos = 0;        
      }
      memcpy ( res, ((CBCMACContext*) context->context)->partial, macSize);
      return SUCCESS;
    }

  /**
   * Computes a non-incremental MAC calculation on the given message. The
   * key from the init() call will be used for the MAC calculation.
   *
   * @param context opaque data structure to hold the module specific state
   *        associated with this invocation of the incremental computation.
   * @param msg a buffer of length size on which the MAC will be calculated
   * @param length the total length of the msg
   * @param buffer of at least macSize where the resulting MAC calculation
   *        will be stored.
   * @param macSzie the number of bytes of MAC to generate. This must be
   *        less than or equal to the underlying blockCipher block size.
   * @return whether the command suceeds or not. It can fail if the underlying
   *        blockCipher fails. 
   */
  async command result_t MAC.MAC (MACContext * context, uint8_t * msg,
				  uint16_t length,
				  uint8_t *res, uint8_t macSize)
    {
      // we'll just call the incremental primitives that we've built:
      dbg(DBG_USR1, "MAC.MAC 1\n");
      if (call MAC.initIncrementalMAC (context, length) != SUCCESS)
        return FAIL;
      dbg(DBG_USR1, "MAC.MAC 2\n");
      if (call MAC.incrementalMAC (context, msg, length) != SUCCESS)
        return FAIL;
      dbg(DBG_USR1, "MAC.MAC 3\n");
      return call MAC.getIncrementalMAC (context, res, macSize);
    }
  
}
