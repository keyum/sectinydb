// $Id: SpiByteFifoC.nc,v 1.2 2003/10/07 21:45:26 idgay Exp $

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
 */
/*									tab:4
 *  IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.  By
 *  downloading, copying, installing or using the software you agree to
 *  this license.  If you do not agree to this license, do not download,
 *  install, copy or use the software.
 *
 *  Intel Open Source License 
 *
 *  Copyright (c) 2002 Intel Corporation 
 *  All rights reserved. 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 * 
 *	Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *	Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *      Neither the name of the Intel Corporation nor the names of its
 *  contributors may be used to endorse or promote products derived from
 *  this software without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE INTEL OR ITS
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 */
/*
 *
 */
module SpiByteFifoC
{
  provides interface SpiByteFifo;
  uses interface SlavePin;
}
implementation
{
  uint8_t nextByte;
  uint8_t state;

  enum {
    IDLE,
    FULL,
    OPEN,
    READING
  };

  enum {
    BIT_RATE = 20 * 4 / 2 * 5/4
  };


  TOSH_SIGNAL(SIG_SPI) {
    uint8_t temp = inp(SPDR);
    outp(nextByte, SPDR);
    state = OPEN;
#ifdef CANBY
  // added these two lines to see if we can get arround the lack of wire
  // between the two pins-- Lakshman
  TOSH_MAKE_FLASH_SELECT_OUTPUT();
  TOSH_CLR_FLASH_SELECT_PIN();
#endif /* CANBY */
    signal SpiByteFifo.dataReady(temp);
  }

  command result_t SpiByteFifo.send(uint8_t data) {
    if(state == OPEN){
      nextByte = data;	
      state = FULL;
      return SUCCESS;
    }if(state == IDLE){
      state = OPEN;
      signal SpiByteFifo.dataReady(0);
      call SlavePin.low();
      cbi(PORTB, 7);
      cbi(PORTB, 0);
      sbi(DDRB, 7);
      outp(0xc0, SPCR);
      outp(data, SPDR);
      //set the radio to TX.
      TOSH_CLR_RFM_CTL0_PIN();
      TOSH_SET_RFM_CTL1_PIN();
      //start the timer.
      cbi(TIMSK, TOIE2);
      cbi(TIMSK, OCIE2);
      outp(0, TCNT2);
      outp(BIT_RATE, OCR2);
      outp(0x19, TCCR2);
      return SUCCESS;
    }
    return FAIL;
  }

  command result_t SpiByteFifo.idle() {
    outp(0x00, SPCR);
    outp(0x00, SPDR);
    outp(0x00, TCCR2);
    nextByte = 0;
    call SlavePin.high(TRUE);
    TOSH_MAKE_RFM_TXD_OUTPUT();
    TOSH_CLR_RFM_TXD_PIN();
    TOSH_CLR_RFM_CTL0_PIN();
    TOSH_CLR_RFM_CTL1_PIN();
    state = IDLE;
    nextByte = 0;
	
    return SUCCESS;
  }

  command result_t SpiByteFifo.startReadBytes(uint16_t timing) {
    if(state == IDLE){
      state = READING;
      //		MAKE_ONE_WIRE_OUTPUT();
      //		CLR_ONE_WIRE_PIN();
      call SlavePin.low();
      outp(0x00, SPCR);
      cbi(PORTB, 7);
      sbi(DDRB, 7);
      outp(0x0, TCCR2);
      outp(0x1, TCNT2);
      outp(BIT_RATE, OCR2);
      //don't change the radio state.
      timing += (400-19);
      if(timing > 0xfff0) timing = 0xfff0;
      //set the phase of the clock line
      outp(0x19, TCCR2);
      outp(BIT_RATE - 20, TCNT2);
      while(inp(PINB) & 0x80){;}
      while(__inw(TCNT1L) < timing){outp(0x0,TCNT2);}
      outp(0xc0, SPCR);
#ifdef CANBY
      // added these two lines to see if we can get arround the lack of wire
      // between the two pins-- Lakshman
      TOSH_MAKE_FLASH_SELECT_OUTPUT();
      TOSH_CLR_FLASH_SELECT_PIN();
#endif /* CANBY */
      outp(0x00, SPDR);
      sbi(PORTB, 6);
      cbi(PORTB, 6);
      return SUCCESS;
    }
    return FAIL;
  }

  command result_t SpiByteFifo.txMode() {
    TOSH_CLR_RFM_CTL0_PIN();
    TOSH_SET_RFM_CTL1_PIN();
    return SUCCESS;
  }

  command result_t SpiByteFifo.rxMode() {
    TOSH_CLR_RFM_TXD_PIN();
    TOSH_MAKE_RFM_TXD_INPUT();
    TOSH_SET_RFM_CTL0_PIN();
    TOSH_SET_RFM_CTL1_PIN();
#ifdef CANBY
     // added these two lines to see if we can get arround the lack of wire
     // between the two pins-- Lakshman
     TOSH_MAKE_FLASH_SELECT_OUTPUT();
     TOSH_CLR_FLASH_SELECT_PIN();
#endif
    return SUCCESS;
  }

  command result_t SpiByteFifo.phaseShift() {
    unsigned char f = inp(TCNT2);
    if(f > 20) f -= 20;
    outp(f, TCNT2);
    return SUCCESS;
  }

  event result_t SlavePin.notifyHigh() {
    return SUCCESS;
  }
}
