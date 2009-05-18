// $Id: TinySecM.nc,v 1.12 2004/06/16 23:26:23 ckarlof Exp $

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

/* Authors: Chris Karlof
 * Date:    8/1/03
 */

/**
 * @author Chris Karlof
 */


module TinySecM
{
  provides {
    interface TinySec;
    interface BareSendMsg as Send;
    interface ReceiveMsg as Receive;
    interface TinySecMode;
    interface TinySecControl;
    interface StdControl;
  }
  uses {
    interface BareSendMsg as RadioSend;
    interface ReceiveMsg as RadioReceive;
    interface BlockCipherMode;
    interface MAC;
    interface Random;
    interface BlockCipherInfo;
    interface TinySecRadio;
    interface Leds;
  }
}

implementation
{
  bool initialized = FALSE;
 
  enum {
    // we allocate some static buffers on the stack; they have to be less
    // than this size
    TINYSECM_MAX_BLOCK_SIZE = 16,
    COMPUTE_MAC_IDLE, // no verify in progress
    COMPUTE_MAC_INITIALIZED, // verify has been initialized and
                             //ready for incremental computation
    COMPUTE_MAC_BUSY, // verify in the middle of incremental computation
    DECRYPT_IDLE, // no decrypt in progress
    DECRYPT_INITIALIZED, // decrypt has been initialized and
                         //is ready for incremental decryption
    DECRYPT_BUSY, // incremental decrypt in progress
    ENCRYPT_IDLE, // no encryption running
    ENCRYPT_BUSY }; // encryption running

  int16_t txlength = 0;
  int16_t rxlength = 0;

  bool txencrypt = TRUE;
  bool rxdecrypt = TRUE;
  
  int16_t TxByteCnt = 0;
  int16_t RxByteCnt = 0;

  int16_t recDataLength = 0;
  int16_t sendDataLength = 0;
  
  uint8_t compute_mac_state;
  uint8_t decrypt_state;
  uint8_t encrypt_state;
  uint8_t blockSize;

  // buffer for posting mac opration for receive
  struct computeMACBuffer {
    bool computeMACWaiting;
    bool computeMACInitWaiting;
    uint8_t position;
    uint8_t amount;
    bool finishMACWaiting;
  } computeMACBuffer;

  // buffer for posting decrypt operations on receive
  struct decryptBuffer {
    bool decryptWaiting;
    bool decryptInitWaiting;
    uint8_t position;
    uint8_t amount;
  } decryptBuffer;

  CipherModeContext cipherModeContext;
  MACContext macContext;

  uint8_t iv[TINYSECM_MAX_BLOCK_SIZE];

  // TinySec buffers
  TinySec_Msg tinysec_rec_buffer;
  TinySec_Msg tinysec_send_buffer;

  TinySec_Msg* ciphertext_send_ptr;
  TinySec_Msg* ciphertext_rec_ptr;

  TOS_Msg_TinySecCompat* cleartext_send_ptr;
  TOS_Msg_TinySecCompat* cleartext_rec_ptr;

  uint8_t encryptionKey[TINYSEC_KEYSIZE];
  uint8_t MACKey[TINYSEC_KEYSIZE];

  uint8_t sendMode = TINYSEC_AUTH_ONLY;
  uint8_t receiveMode = TINYSEC_RECEIVE_AUTHENTICATED;
  
  /**
   * Initializes TinySec. BlockCipherMode and MAC contexts are initialized 
   * with respective keys, key size, and block size.
   *
   * @param blockSize block size of the block cipher in bytes
   * @param keySize key size of the block cipher in bytes
   * @param encryptionKey pointer to an array of keySize bytes 
   *        representing the key used for encryption
   * @param MACKey pointer to an array of keySize bytes 
   *        representing the key used for calculating MAC's
   * @return Whether TinySec initialization was successful. Reasons 
   *         for failure include BlockCipherMode or MAC init()
   */
  command result_t StdControl.init() {
    result_t r1, r2, r3, r4;
    int i, local_addr;
    uint8_t tmp = call BlockCipherInfo.getPreferredBlockSize();
    uint8_t key_tmp[2*TINYSEC_KEYSIZE] = {TINYSEC_KEY};

    memcpy(encryptionKey,key_tmp,TINYSEC_KEYSIZE);
    memcpy(MACKey,key_tmp+TINYSEC_KEYSIZE,TINYSEC_KEYSIZE);    
    
    atomic {
      if(tmp > TINYSECM_MAX_BLOCK_SIZE) {
	blockSize = 0;
	r3 = FAIL;
      }
      else {
	blockSize = tmp;
	r3 = SUCCESS;
      }
    
      computeMACBuffer.computeMACWaiting = FALSE;
      computeMACBuffer.computeMACInitWaiting = FALSE;
      compute_mac_state = COMPUTE_MAC_IDLE;
      decrypt_state = DECRYPT_IDLE;
      encrypt_state = ENCRYPT_IDLE;
      decryptBuffer.decryptWaiting = FALSE;
      decryptBuffer.decryptInitWaiting = FALSE;
      
      computeMACBuffer.finishMACWaiting = FALSE;
    
      // FIXME: replace this with EEPROM read or random IV
      // since IV is reset on reboots, this is bad
      for(i=0;i<blockSize;i++) {
	iv[i] = 0;
      }

      if(TINYSEC_IV_LENGTH < TINYSEC_NODE_ID_SIZE)
	r4 = FAIL;
      else
	r4 = SUCCESS;

      // write the source address into the 3rd and 4th bytes of iv
      local_addr = TOS_LOCAL_ADDRESS;
      iv[TINYSEC_IV_LENGTH-TINYSEC_NODE_ID_SIZE] = local_addr & 0xff;
      for(i=1;i<TINYSEC_NODE_ID_SIZE;i++) {
	local_addr = local_addr >> 8;
	iv[TINYSEC_IV_LENGTH-TINYSEC_NODE_ID_SIZE+i] = local_addr & 0xff;
      }
    }
    r1 = call BlockCipherMode.init(&cipherModeContext,TINYSEC_KEYSIZE,encryptionKey);
    r2 = call MAC.init(&macContext,TINYSEC_KEYSIZE,MACKey);
    if(rcombine(rcombine(r1,r2),rcombine(r3,r4)) == FAIL)
      return FAIL;
    else {
      atomic {
	initialized = TRUE;
      }
      return SUCCESS;
    }
  }

  command result_t StdControl.start() {
    return SUCCESS;
  }

  command result_t StdControl.stop() {
    return SUCCESS;
  }

  command result_t TinySecControl.updateMACKey(uint8_t * newMACKey) {
    result_t result = FAIL;
    
    atomic {
      if(!initialized ||
	 compute_mac_state != COMPUTE_MAC_IDLE ||
	 encrypt_state != ENCRYPT_IDLE ||
	 decrypt_state != DECRYPT_IDLE)
	  result = FAIL;
      else { // TinySec is idle
	memcpy(MACKey,newMACKey,TINYSEC_KEYSIZE);
 	result = call MAC.init(&macContext,TINYSEC_KEYSIZE,MACKey);
      }
    }
    return result;
  }

  command result_t TinySecControl.getMACKey(uint8_t * result) {
    if(!initialized)
      return FAIL;
    atomic memcpy(result,MACKey,TINYSEC_KEYSIZE);
    return SUCCESS;
  }
  
  command result_t TinySecControl.updateEncryptionKey(uint8_t * newEncryptionKey) {
    result_t result = FAIL;
    
    atomic {
      if(!initialized ||
	 compute_mac_state != COMPUTE_MAC_IDLE ||
	 encrypt_state != ENCRYPT_IDLE ||
	 decrypt_state != DECRYPT_IDLE)
	  result = FAIL;
      else { // TinySec is idle
	memcpy(encryptionKey,newEncryptionKey,TINYSEC_KEYSIZE);
	// reset IV
 	result = call BlockCipherMode.init(&cipherModeContext,TINYSEC_KEYSIZE,
					   encryptionKey);
      }
    }
    return result;   
  }

  command result_t TinySecControl.getEncryptionKey(uint8_t * result) {
    if(!initialized)
      return FAIL;
    atomic memcpy(result,encryptionKey,TINYSEC_KEYSIZE);
    return SUCCESS;
  }

  command result_t TinySecControl.resetIV() {
    result_t result = FAIL;

    atomic {
      if(!initialized ||
	 compute_mac_state != COMPUTE_MAC_IDLE ||
	 encrypt_state != ENCRYPT_IDLE ||
	 decrypt_state != DECRYPT_IDLE)
	result = FAIL;
      else {
	memset(iv,0,TINYSEC_IV_LENGTH-TINYSEC_NODE_ID_SIZE);
	result = SUCCESS;
      }
    }
    // need to reupdate ID part of IV if we ever use anything
    // other TOS_LOCAL_ADDRESS
    return result;
  }

  command result_t TinySecControl.getIV(uint8_t * result) {
    if(!initialized)
      return FAIL;
    atomic memcpy(result,iv,TINYSEC_IV_LENGTH);
    return SUCCESS;
  }
  
  command result_t Send.send(TOS_MsgPtr msg) {
    if(sendMode == TINYSEC_AUTH_ONLY)
      msg->length = msg->length | TINYSEC_ENABLED_BIT;
    else if(sendMode == TINYSEC_ENCRYPT_AND_AUTH)
      msg->length = msg->length | TINYSEC_ENABLED_BIT |
	TINYSEC_ENCRYPT_ENABLED_BIT;
    else if(sendMode != TINYSEC_DISABLED)
      return FAIL;
   
    return call RadioSend.send(msg);
  }

  event result_t RadioSend.sendDone(TOS_MsgPtr msg, result_t success) {
    msg->length = msg->length & ~(TINYSEC_ENABLED_BIT |
				  TINYSEC_ENCRYPT_ENABLED_BIT);
    return signal Send.sendDone(msg,success);
  }
    
  event TOS_MsgPtr RadioReceive.receive(TOS_MsgPtr msg) {

    if(msg->length & TINYSEC_ENABLED_BIT) {
      if(msg->length & TINYSEC_ENCRYPT_ENABLED_BIT) {
	msg->receiveSecurityMode = TINYSEC_ENCRYPT_AND_AUTH;
      }
      else {
	msg->receiveSecurityMode = TINYSEC_AUTH_ONLY;
      }
    } else {
      msg->receiveSecurityMode = TINYSEC_DISABLED;
    }
    
    if(receiveMode == TINYSEC_RECEIVE_ANY) {
      if(msg->length & TINYSEC_ENABLED_BIT) {
	msg->length = msg->length & ~(TINYSEC_ENABLED_BIT |
				      TINYSEC_ENCRYPT_ENABLED_BIT);
      }
      return signal Receive.receive(msg);
    }

    // not sure if this is the right way to do this. should we trust
    // higher level to check crc?
    if(msg->length & TINYSEC_ENABLED_BIT) {
      msg->length = msg->length & ~(TINYSEC_ENABLED_BIT |
				    TINYSEC_ENCRYPT_ENABLED_BIT);
      if(receiveMode == TINYSEC_RECEIVE_AUTHENTICATED)
	return signal Receive.receive(msg);
      else
	return msg;
    } else {
      if(receiveMode == TINYSEC_RECEIVE_CRC)
	return signal Receive.receive(msg);
      else
	return msg;
    }
  }

  command result_t TinySecMode.setTransmitMode(uint8_t mode) {
    if(mode == TINYSEC_ENCRYPT_AND_AUTH ||
       mode == TINYSEC_AUTH_ONLY ||
       mode == TINYSEC_DISABLED) {
      sendMode = mode;
      return SUCCESS;
    } else
      return FAIL;
  }

  command result_t TinySecMode.setReceiveMode(uint8_t mode) {
    if(mode == TINYSEC_RECEIVE_AUTHENTICATED ||
       mode == TINYSEC_RECEIVE_CRC ||
       mode == TINYSEC_RECEIVE_ANY) {
      receiveMode = mode;
      return SUCCESS;
    } else
      return FAIL;
  }

  command uint8_t TinySecMode.getTransmitMode() {
    return sendMode;
  }

  command uint8_t TinySecMode.getReceiveMode() {
    return receiveMode;
  }
  
  result_t decryptIncrementalInit();
  result_t decryptIncremental(uint8_t incr_decrypt_start, uint8_t amount);
  result_t MACincrementalInit();
  result_t computeMACIncremental(uint8_t incr_mac_start, uint8_t amount);
  result_t computeMACIncrementalFinish();
  result_t verifyMAC();
  result_t computeMAC();
  result_t encrypt();
  result_t noEncrypt();
  result_t checkedQueuedCrypto();


  bool interruptDisable() {
    bool result = (inp(SREG) & 0x80) != 0;
    cli();
    return result;
  }

  result_t interruptEnable() {
    sei();
    return SUCCESS;
  }
  
  result_t postIncrementalMACInit() {
    computeMACBuffer.computeMACInitWaiting = TRUE;
    return SUCCESS;
  }

  result_t postIncrementalMAC(uint8_t incr_mac_start, uint8_t amount) {
    if(computeMACBuffer.computeMACWaiting) {
      computeMACBuffer.amount += amount;
    } else {
      computeMACBuffer.computeMACWaiting = TRUE;
      computeMACBuffer.position = incr_mac_start;
      computeMACBuffer.amount = amount;
    }
    return SUCCESS;
  }

  result_t postIncrementalMACFinish() {
    computeMACBuffer.finishMACWaiting = TRUE;
    return SUCCESS;
  }

  result_t postIncrementalDecryptInit() {
    decryptBuffer.decryptInitWaiting = TRUE;
    return SUCCESS;
  }
    
  result_t postIncrementalDecrypt(uint8_t incr_decrypt_start, uint8_t amount) {
    if(decryptBuffer.decryptWaiting) {
      decryptBuffer.amount += amount;
    } else {
      decryptBuffer.decryptWaiting = TRUE;
      decryptBuffer.position = incr_decrypt_start;
      decryptBuffer.amount = amount;
    }
    return SUCCESS;
  }
  
  result_t checkQueuedCrypto() {
    result_t result = SUCCESS;

    // crypto operation already in progress
    if(compute_mac_state == COMPUTE_MAC_BUSY || decrypt_state == DECRYPT_BUSY)
      return SUCCESS;
    
    if(computeMACBuffer.computeMACInitWaiting) {
      computeMACBuffer.computeMACInitWaiting = FALSE;
      result = rcombine(result,MACincrementalInit());
    }
      
    if(computeMACBuffer.computeMACWaiting) {
      computeMACBuffer.computeMACWaiting = FALSE;
      result = rcombine(result,computeMACIncremental(computeMACBuffer.position,
						     computeMACBuffer.amount));
    }
    // check waiting state and finish up work
    if(computeMACBuffer.finishMACWaiting) {
      computeMACBuffer.finishMACWaiting = FALSE;
      result = rcombine(result,computeMACIncrementalFinish());
    }
    if(decryptBuffer.decryptInitWaiting) {
      decryptBuffer.decryptInitWaiting = FALSE;
      result = rcombine(result,decryptIncrementalInit());
    }
    if(decryptBuffer.decryptWaiting) {
      decryptBuffer.decryptWaiting = FALSE;
      if(decrypt_state == DECRYPT_INITIALIZED) {
	result = rcombine(result,decryptIncremental(decryptBuffer.position,
						    decryptBuffer.amount));
      } else if (decrypt_state == DECRYPT_IDLE) {
	result = rcombine(result,decryptIncrementalInit());
      } else {
	return FAIL;
      }
    }
    return result;
  }
  
  // WARNING: this function makes assumptions about the stucture of TinySec_Msg!
  // Incremental MAC computation must be initialized before this is called.
  result_t decryptIncrementalInit() {
    uint8_t decrypt_iv[TINYSECM_MAX_BLOCK_SIZE];
    int i;
    result_t result;
    uint16_t ivLengthRemaining = sizeof(ciphertext_rec_ptr->addr) +
      sizeof(ciphertext_rec_ptr->type) +
      sizeof(ciphertext_rec_ptr->length);

    if(decrypt_state != DECRYPT_IDLE || !initialized)
      return FAIL;
   
    decrypt_state = DECRYPT_BUSY;
    interruptEnable();
    
    if(ivLengthRemaining > (blockSize - TINYSEC_IV_LENGTH))
      ivLengthRemaining = blockSize - TINYSEC_IV_LENGTH;
    
    // copy current iv into cipher buffer iv field
    memcpy(decrypt_iv,ciphertext_rec_ptr->iv,TINYSEC_IV_LENGTH);
    // fill in remaining space with addr, AM type, and length
    memcpy(decrypt_iv+TINYSEC_IV_LENGTH,&(ciphertext_rec_ptr->addr),
	   ivLengthRemaining);
    
    // zero out the rest of the iv
    for(i=ivLengthRemaining+TINYSEC_IV_LENGTH;i<blockSize;i++) {
      decrypt_iv[i] = 0;
    }
    // if less than one block, then use one block.
    // assumes buffer has been padded.
    if(recDataLength < blockSize) {
      result = call BlockCipherMode.initIncrementalDecrypt(&cipherModeContext,
							   decrypt_iv,
							   blockSize);
      dbg(DBG_CRYPTO,"DECRYPT: init size=%d\n",blockSize);
    }
    else {
      result = call BlockCipherMode.initIncrementalDecrypt(&cipherModeContext,
							   decrypt_iv,
							   recDataLength);
      dbg(DBG_CRYPTO,"DECRYPT: init size=%d\n",recDataLength);
    }
    
    interruptDisable();
    decrypt_state = DECRYPT_INITIALIZED;
    result = rcombine(result,checkQueuedCrypto());
    return result;
  }

  result_t decryptIncremental(uint8_t incr_decrypt_start, uint8_t amount) {
    result_t result;
    uint16_t done;

    if(!initialized)
      return FAIL;

    if(decrypt_state == DECRYPT_IDLE) {
      return FAIL; // error
    } else if(decrypt_state == DECRYPT_INITIALIZED) {
      decrypt_state = DECRYPT_BUSY;
      interruptEnable();
      result = call BlockCipherMode.incrementalDecrypt(
			     &cipherModeContext,
			     (ciphertext_rec_ptr->enc)+incr_decrypt_start,
			     cleartext_rec_ptr->data,amount,
			     &done);
      interruptDisable();
      decrypt_state = DECRYPT_INITIALIZED;
      if(recDataLength < blockSize) {
	if(done == blockSize) {
	  decrypt_state = DECRYPT_IDLE;
	}
      } else {
	if(done == recDataLength) {
	  decrypt_state = DECRYPT_IDLE;
	}
      }
      // shouldn't have any pending decrypts but if someone decides to reorder
      // mac computes and decrypts, we should keep this here (mac computes are
      // currently given priority)
      result = rcombine(result,checkQueuedCrypto());
      return result;
    } else {
      return FAIL; // error
    }
  }
 
  result_t MACincrementalInit() {
    result_t result;
    if(compute_mac_state != COMPUTE_MAC_IDLE || !initialized)
      return FAIL;
    
    compute_mac_state = COMPUTE_MAC_BUSY;
    interruptEnable();
    result = call MAC.initIncrementalMAC(&macContext,rxlength);
    dbg(DBG_CRYPTO,"MAC init called: rxlength=%d.\n",rxlength);
    interruptDisable();
    compute_mac_state = COMPUTE_MAC_INITIALIZED;
    result = rcombine(result,checkQueuedCrypto());
    return result;
  }


  result_t computeMACIncremental(uint8_t incr_mac_start, uint8_t amount) {
    if(!initialized)
      return FAIL;
    if(incr_mac_start >= TINYSEC_MSG_DATA_SIZE - TINYSEC_MAC_LENGTH)
      return FAIL;
    
    if(compute_mac_state == COMPUTE_MAC_IDLE) {
      return FAIL; // has not been initialized
    } else if(compute_mac_state == COMPUTE_MAC_INITIALIZED) {
      result_t result;
      compute_mac_state = COMPUTE_MAC_BUSY;
      interruptEnable();
      result = call MAC.incrementalMAC(
			 &macContext,
		         ((uint8_t*) ciphertext_rec_ptr)+incr_mac_start,amount);
      interruptDisable();
      compute_mac_state = COMPUTE_MAC_INITIALIZED;
      result = rcombine(result,checkQueuedCrypto());
      return result;
    } else {
      return FAIL;
    }
  }

  result_t computeMACIncrementalFinish() {
    if(!initialized)
      return FAIL;
    
    if(compute_mac_state == COMPUTE_MAC_IDLE) {
      // this is an error. state should be unreachable
      return FAIL;
    } else if(compute_mac_state == COMPUTE_MAC_INITIALIZED) { 
      result_t result;
      compute_mac_state = COMPUTE_MAC_BUSY;
      interruptEnable();
      result = call MAC.getIncrementalMAC(
				     &macContext,
				     ciphertext_rec_ptr->calc_mac,
				     TINYSEC_MAC_LENGTH+TINYSEC_ACK_LENGTH);
      interruptDisable();
      ciphertext_rec_ptr->MACcomputed = TRUE;
      if(ciphertext_rec_ptr->receiveDone) {
	verifyMAC();
      }
      compute_mac_state = COMPUTE_MAC_IDLE;
      result = rcombine(result,checkQueuedCrypto());
      return result;
    } else {
      return FAIL;
    }
  }

  result_t verifyMAC() {
    int i;

    if(!initialized) 
      return FAIL;

    // indicates incremental MAC computation has not completed
    if(!ciphertext_rec_ptr->MACcomputed) {
      return FAIL;
    }

    dbg(DBG_CRYPTO,"MAC computed: %hx %hx %hx %hx, "
	"MAC received: %hx %hx %hx %hx\n",
	(ciphertext_rec_ptr->calc_mac)[0],
	(ciphertext_rec_ptr->calc_mac)[1],
	(ciphertext_rec_ptr->calc_mac)[2],
	(ciphertext_rec_ptr->calc_mac)[3],
	(ciphertext_rec_ptr->mac)[0],
	(ciphertext_rec_ptr->mac)[1],
	(ciphertext_rec_ptr->mac)[2],
	(ciphertext_rec_ptr->mac)[3]);
    // verify calculated MAC with one received in packet
    for(i=0;i<TINYSEC_MAC_LENGTH;i++) {
      if((ciphertext_rec_ptr->calc_mac)[i] != (ciphertext_rec_ptr->mac)[i]) {
        dbg(DBG_CRYPTO,"Invalid MAC byte %d - calcmac:%hx ciphermac:%hx\n",i,
	    (ciphertext_rec_ptr->calc_mac)[i],
	    (ciphertext_rec_ptr->mac)[i]);
	ciphertext_rec_ptr->MACcomputed = FALSE;
	cleartext_rec_ptr->crc = 0;
	return SUCCESS;
      }
    }
    cleartext_rec_ptr->crc = 1;
    return SUCCESS;
  }

  /***************** Receive code *****************************/

  async command result_t TinySec.receiveInit(
				        TOS_Msg_TinySecCompat* cleartext_ptr) {
    ciphertext_rec_ptr = &tinysec_rec_buffer;
    cleartext_rec_ptr = cleartext_ptr;
    RxByteCnt = 0;
    rxlength = TINYSEC_MSG_DATA_SIZE-TINYSEC_MAC_LENGTH;
    rxdecrypt = FALSE;
    
    // initialize state variables in receive buffer
    ciphertext_rec_ptr->cryptoDone = FALSE;
    ciphertext_rec_ptr->receiveDone = FALSE;
    ciphertext_rec_ptr->MACcomputed = FALSE;
    
    // reset crypto buffer variables
    computeMACBuffer.computeMACWaiting = FALSE;
    computeMACBuffer.computeMACInitWaiting = FALSE;
    decryptBuffer.decryptWaiting = FALSE;
    decryptBuffer.decryptInitWaiting = FALSE;
    computeMACBuffer.finishMACWaiting = FALSE;
    
    // flush crc
    cleartext_rec_ptr->crc = 0;
 
    return SUCCESS;
  }
    
  async event result_t TinySecRadio.byteReceived(uint8_t byte) {
    int8_t macRecCount=-1, decryptRecCount=-1;
    if(RxByteCnt < rxlength) {
      // this branch statement is a hack for when we skip
      // over the IV for non-encrypted packets. we add the TINYSEC_IV_SIZE 
      if(RxByteCnt == offsetof(struct TinySec_Msg,iv) && !rxdecrypt) {
	RxByteCnt += TINYSEC_IV_LENGTH;
	((uint8_t *) ciphertext_rec_ptr)[(int)RxByteCnt] = byte;
	RxByteCnt++;
	macRecCount = ((RxByteCnt - TINYSEC_IV_LENGTH) & (blockSize-1)) +
	  TINYSEC_IV_LENGTH;
	decryptRecCount = RxByteCnt - offsetof(struct TinySec_Msg,enc); 
      } else {
	((uint8_t *) ciphertext_rec_ptr)[(int)RxByteCnt] = byte;
	RxByteCnt++;
	macRecCount = RxByteCnt & (blockSize-1);
	decryptRecCount = RxByteCnt - offsetof(struct TinySec_Msg,enc);
      }
    } else if(RxByteCnt < rxlength + TINYSEC_IV_LENGTH) {
      ciphertext_rec_ptr->mac[RxByteCnt-rxlength] = byte;
      RxByteCnt++;
    }
    
    dbg(DBG_CRYPTO,"TINYSEC: byteReceived() RxByteCnt=%d data=%hx "
	"recDataLength=%d macRecCount=%d decryptRecCount=%d.\n",
	RxByteCnt,byte,recDataLength,macRecCount,decryptRecCount);	
    
    if(RxByteCnt < rxlength) {
      if(RxByteCnt == (offsetof(struct TinySec_Msg,length) + 
		       sizeof(((struct TinySec_Msg *)0)->length))) {
	// get real length
	recDataLength = ciphertext_rec_ptr->length &
	  (TINYSEC_ENCRYPT_ENABLED_BIT-1);
	
	// we signal fail if message length is greater than DATA_LENGTH.
	// however, when TinySec is disabled it is possible to support
	// packets up to 127 bytes. Change here to enable that.
	if(recDataLength > DATA_LENGTH) {
	  signal TinySec.receiveInitDone(FAIL,0,FALSE);
	  return SUCCESS;
	}
	if(ciphertext_rec_ptr->length & TINYSEC_ENABLED_BIT) {
	  dbg(DBG_CRYPTO,"Detected TinySec bit.\n");
	  if(ciphertext_rec_ptr->length & TINYSEC_ENCRYPT_ENABLED_BIT) {
	    dbg(DBG_CRYPTO,"Encryption enabled.\n");
	    rxdecrypt = TRUE;
	  } else {
	    dbg(DBG_CRYPTO,"Encryption disabled.\n");
	    rxdecrypt = FALSE;
	  }
	  rxlength = offsetof(struct TinySec_Msg,enc);
	  
	  if(recDataLength < blockSize && rxdecrypt)
	    rxlength += blockSize;
	  else
	    rxlength += recDataLength;
	  
	  if(rxdecrypt) {
	    signal TinySec.receiveInitDone(SUCCESS,rxlength,TRUE);
	  } else {
	    // zero out iv if encryption is not enabled
	    memset(ciphertext_rec_ptr->iv,0,TINYSEC_IV_LENGTH);
	    signal TinySec.receiveInitDone(SUCCESS,
					   rxlength-TINYSEC_IV_LENGTH,TRUE);
	  }
	  postIncrementalMACInit();
	} else { // TinySec not enabled
	  rxlength = recDataLength + offsetof(struct TOS_Msg_TinySecCompat,
					      data);
	  signal TinySec.receiveInitDone(SUCCESS,rxlength,FALSE);
	}
      } else { // not length byte.
	// bytes before length byte will fail following checks.
	// this weird check is needed because of when we
	// skip RxByteCnt over the IV when encryption in not enabled.

	// zero macRecCount means we have received blockSize bytes
	if(macRecCount == 0)
	  macRecCount = blockSize;
	if(macRecCount >= blockSize) {
	  // post MAC operation
	  postIncrementalMAC(RxByteCnt-macRecCount,blockSize);
	}
	
	if(rxdecrypt) {
	  if(decryptRecCount == 0) {
	    postIncrementalDecryptInit();
	  } else if((decryptRecCount & (blockSize-1)) == 0) {
	    postIncrementalDecrypt(decryptRecCount-blockSize,blockSize);
	  }
	}
      }
      checkQueuedCrypto();
    } else if(RxByteCnt == rxlength) {
      if(macRecCount == 0)
	macRecCount = blockSize;
      postIncrementalMAC(RxByteCnt-macRecCount,macRecCount);
      postIncrementalMACFinish();
      if(rxdecrypt) {
	if((decryptRecCount & (blockSize-1)) == 0) {
	  postIncrementalDecrypt(decryptRecCount-blockSize,blockSize);
	}
	else {
	  postIncrementalDecrypt(
			   decryptRecCount-(decryptRecCount & (blockSize-1)),
			   decryptRecCount & (blockSize-1));
	}
      } else {
	memcpy(cleartext_rec_ptr->data,ciphertext_rec_ptr->enc,recDataLength);
      }
      checkQueuedCrypto();
      ciphertext_rec_ptr->cryptoDone = TRUE;
      cleartext_rec_ptr->group = TOS_AM_GROUP;
      if(ciphertext_rec_ptr->receiveDone) {	
	signal TinySec.receiveDone(SUCCESS);
      }
    } else if(RxByteCnt == rxlength + TINYSEC_IV_LENGTH) { 
      ciphertext_rec_ptr->receiveDone = TRUE;
      if(ciphertext_rec_ptr->MACcomputed)
	verifyMAC();
      if(ciphertext_rec_ptr->cryptoDone) {
	signal TinySec.receiveDone(SUCCESS);
      }
    } else { // we have an error
      return FAIL;
    } 
    
    return SUCCESS;
  }

    
  /****************** Send code ****************************/

  async command uint16_t TinySec.sendInit(TOS_Msg_TinySecCompat* cleartext_ptr) {
    cleartext_send_ptr = cleartext_ptr;
    ciphertext_send_ptr = &tinysec_send_buffer;

    ciphertext_send_ptr->addr = cleartext_send_ptr->addr;
    ciphertext_send_ptr->length = cleartext_send_ptr->length;
    ciphertext_send_ptr->type = cleartext_send_ptr->type;

    sendDataLength = cleartext_send_ptr->length &
      (TINYSEC_ENCRYPT_ENABLED_BIT-1);
    dbg(DBG_CRYPTO,"TINYSEC: sendInit() Sending length = %d\n",sendDataLength);
    dbg(DBG_CRYPTO,"TINYSEC: sendInit() Length field = %d\n",
	ciphertext_send_ptr->length);

    // fix length fields that are too long
    if(sendDataLength > DATA_LENGTH) {
      sendDataLength = DATA_LENGTH;
      ciphertext_send_ptr->length = DATA_LENGTH | TINYSEC_ENABLED_BIT |
	(cleartext_send_ptr->length & TINYSEC_ENCRYPT_ENABLED_BIT);
    }
    
    if(cleartext_send_ptr->length & TINYSEC_ENCRYPT_ENABLED_BIT)
      txencrypt = TRUE;
    else
      txencrypt = FALSE;

    if(sendDataLength < blockSize && txencrypt) {
      txlength = blockSize + TINYSEC_MSG_DATA_SIZE - DATA_LENGTH -
	TINYSEC_MAC_LENGTH;
    } else {
      txlength = sendDataLength + TINYSEC_MSG_DATA_SIZE - DATA_LENGTH -
	TINYSEC_MAC_LENGTH;
    }

    TxByteCnt = -1;
    
    return txlength;    
  }

  result_t computeMAC() {
    result_t result = call MAC.MAC(&macContext,
				   (uint8_t*) &(ciphertext_send_ptr->addr),     
				   txlength,
				   ciphertext_send_ptr->calc_mac,
				   TINYSEC_MAC_LENGTH+TINYSEC_ACK_LENGTH);
    // copy calculated mac to mac field. reason is because extra byte
    // was calculated and stored in ack_byte. ack_byte is
    // currently not used.
    memcpy(ciphertext_send_ptr->mac,ciphertext_send_ptr->calc_mac,
	   TINYSEC_MAC_LENGTH);
    dbg(DBG_CRYPTO,"MAC: computed: %hx %hx %hx %hx\n",
	(ciphertext_send_ptr->mac)[0],
	(ciphertext_send_ptr->mac)[1],
	(ciphertext_send_ptr->mac)[2],
	(ciphertext_send_ptr->mac)[3]);
    return result;
  }

  // for padding out input less than a block size
  result_t addPadding(TOS_Msg_TinySecCompat* bufptr, uint16_t dataLength) {
    uint16_t r = call Random.rand();
    uint8_t i = 0;
    for(i=dataLength;i<blockSize-1;i=i+2) {
      memcpy((bufptr->data)+i,&r,2);
      r = call Random.rand();
    }
    if(i == (blockSize-1)) {
      memcpy((bufptr->data)+i,&r,1);
    }
    return SUCCESS;
  }
  
  result_t encrypt() {
    // number of header bytes we use for implicit IV
    uint16_t ivLengthRemaining = sizeof(ciphertext_send_ptr->addr) +
      sizeof(ciphertext_send_ptr->type) + sizeof(ciphertext_send_ptr->length);
    result_t result;
    uint8_t i;
    
    if(ivLengthRemaining > (blockSize - TINYSEC_IV_LENGTH))
      ivLengthRemaining = blockSize - TINYSEC_IV_LENGTH;

    // copy current iv into cipher buffer iv field
    memcpy(&(ciphertext_send_ptr->iv),iv,TINYSEC_IV_LENGTH);
    // fill in remaining space with addr, AM type, and length
    memcpy(iv+TINYSEC_IV_LENGTH,&(ciphertext_send_ptr->addr),ivLengthRemaining);
 
    // zero out the rest of the iv
    for(i=ivLengthRemaining+TINYSEC_IV_LENGTH;i<blockSize;i++) {
      iv[i] = 0;
    }

    if(sendDataLength < blockSize) {
      // pad if data length less than blockSize
      addPadding(cleartext_send_ptr,sendDataLength);
      result = call BlockCipherMode.encrypt(&cipherModeContext,
					    cleartext_send_ptr->data,
					    ciphertext_send_ptr->enc,
					    blockSize,iv);
    } else {
      result = call BlockCipherMode.encrypt(&cipherModeContext,
					    cleartext_send_ptr->data,
					    ciphertext_send_ptr->enc,
					    sendDataLength,iv);
    }
    
    i=0;
    // update IV by one
    // last two bytes of explicit IV is TOS_LOCAL_ADDRESS
    while(i<TINYSEC_IV_LENGTH-TINYSEC_NODE_ID_SIZE) { 
      if(iv[i] == 0xff) {
	iv[i] = 0;
      } else {
	iv[i] = iv[i] + 1;
	break;
      }
      i++;
    }
    return result;
    
  }

  result_t noEncrypt() {
    // zero out IV if no encryption
    memset(ciphertext_send_ptr->iv,0,TINYSEC_IV_LENGTH);
    memcpy(ciphertext_send_ptr->enc,cleartext_send_ptr->data,sendDataLength);
    return SUCCESS;
  }
    
  async command result_t TinySec.send() {
    result_t r1,r2;
    
    encrypt_state = ENCRYPT_BUSY;
    interruptEnable();
    if(txencrypt)
      r1 = encrypt();
    else 
      r1 = noEncrypt();
    atomic {
      encrypt_state = ENCRYPT_IDLE;
      compute_mac_state = COMPUTE_MAC_BUSY;
    }
    r2 = computeMAC();
    interruptDisable();
    compute_mac_state = COMPUTE_MAC_IDLE;
    
    return rcombine(r1,r2);
    
  }
  
  async event uint8_t TinySecRadio.getTransmitByte() {
    uint8_t NextTxByte=0;
    TxByteCnt++;
    if (TxByteCnt < txlength) {
      // skip iv if encryption not enabled
      if(TxByteCnt == offsetof(struct TinySec_Msg, iv) && !txencrypt)
	TxByteCnt += TINYSEC_IV_LENGTH;
      NextTxByte = ((uint8_t *)&tinysec_send_buffer)[(TxByteCnt)];
      dbg(DBG_CRYPTO,"TINYSEC: getTransmitByte() byte=%d data=%hx\n",
	  TxByteCnt+1,NextTxByte);
    } else if(TxByteCnt < txlength + TINYSEC_MAC_LENGTH) {
      NextTxByte = tinysec_send_buffer.mac[TxByteCnt-txlength];
      dbg(DBG_CRYPTO,"TINYSEC: getTransmitByte() byte=%d data=%hx\n",
	  TxByteCnt+1,NextTxByte);
      if(TxByteCnt == txlength + TINYSEC_MAC_LENGTH - 1) {
	signal TinySec.sendDone(SUCCESS);
	dbg(DBG_CRYPTO,"TINYSEC: getTransmitByte() signaling send done\n");
      }
    } else { // this is an error state
      dbg(DBG_CRYPTO,"TINYSEC: getTransmitByte() signaling send done (FAIL)\n");
      signal TinySec.sendDone(FAIL);
    }
    
    return NextTxByte;
  }


  
}
