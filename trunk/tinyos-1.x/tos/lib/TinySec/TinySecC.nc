// $Id: TinySecC.nc,v 1.4 2004/06/16 23:26:23 ckarlof Exp $

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
 * Date:    12/23/02
 */

/**
 * @author Chris Karlof
 */


includes CryptoPrimitives;

configuration TinySecC
{
  provides {
    interface TinySec;
    interface StdControl;
    interface BlockCipherInfo;
    interface BareSendMsg as Send;
    interface ReceiveMsg as Receive;
    interface TinySecMode;
    interface TinySecControl; 
  }

  uses {
    interface TinySecRadio;
    interface BareSendMsg as RadioSend;
    interface ReceiveMsg as RadioReceive;
  }
}
implementation
{
  components TinySecM, RandomLFSR,
    SkipJackM as Cipher,
    //IdentityCipherM as Cipher,
    CBCModeM as Mode,
    //IdentityModeM as Mode,
    CBCMAC as Mac,
    LedsC;

  StdControl = TinySecM.StdControl;
  Send = TinySecM.Send;
  Receive = TinySecM.Receive;
  RadioSend = TinySecM.RadioSend;
  RadioReceive = TinySecM.RadioReceive;
  TinySecMode = TinySecM.TinySecMode;
  TinySecControl = TinySecM.TinySecControl;
  
  TinySecM.BlockCipherMode -> Mode.BlockCipherMode;
  TinySecM.MAC -> Mac.MAC;
  TinySecM.Random -> RandomLFSR.Random;

  Mac.BlockCipher -> Cipher;
  Mode.BlockCipher -> Cipher;
  Mac.BlockCipherInfo -> Cipher;
  Mode.BlockCipherInfo -> Cipher.BlockCipherInfo;
  TinySecM.BlockCipherInfo -> Cipher.BlockCipherInfo;
  BlockCipherInfo = Cipher.BlockCipherInfo;
  TinySec = TinySecM.TinySec;
  TinySecRadio = TinySecM.TinySecRadio;
  TinySecM.Leds -> LedsC;
}
