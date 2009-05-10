// $Id: SimpleTimeM.nc,v 1.2 2003/10/07 21:46:21 idgay Exp $

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

/*
 *

 * Date last modified:  9/25/02
 *
 */

/**
 * @author Su Ping  (sping@intel-research.net)
 */


includes TosTime;
includes Timer;
includes AbsoluteTimer;

module SimpleTimeM {
  provides {
    interface StdControl;
    interface Time;
    interface TimeSet;
    interface AbsoluteTimer[uint8_t id];

    async command void setInterval(uint16_t new_interval);
    async command uint16_t getInterval();
  }
  uses {
    interface Timer;
    interface TimeUtil;
    interface StdControl as TimerControl;
    interface Leds;
  }
}
implementation
{

  uint16_t interval;
  tos_time_t time;
  tos_time_t aTimer[MAX_NUM_TIMERS];
  bool timingChanged;

  command result_t StdControl.init() {
    // initialize logical time
    atomic {
      time.high32=0; 
      time.low32 =0;
      interval = 32;
      timingChanged = FALSE;
    }
    call TimerControl.init();


    return SUCCESS;
  }

  command result_t StdControl.start() {
    uint16_t cur_interval;

    call TimerControl.start();
    atomic { cur_interval = interval; }
    call Timer.start(TIMER_REPEAT, cur_interval);
    return SUCCESS ;
  }

  command result_t StdControl.stop() {
    call Timer.stop();
    call TimerControl.stop();
    return SUCCESS;
  }

  async command uint16_t getInterval() {
    uint16_t cur_interval;
    atomic {
      cur_interval = interval;
    }
    return cur_interval;

  }

  async command void setInterval(uint16_t new_interval) {

    atomic {
      interval = new_interval;
      timingChanged = TRUE;
    }
  }

  async command uint16_t Time.getUs() {
    return 0;
  }

  async command tos_time_t Time.get() {
    tos_time_t t;

    atomic t = time;
    return t;
  }

  async command uint32_t Time.getHigh32()  {
    uint32_t rval;
    atomic {
      rval = time.high32;
    }
    return rval;
  }

  async command uint32_t Time.getLow32() {
    uint32_t rval;
    atomic {
      rval = time.low32;
    }
    return rval;
  }

  command result_t AbsoluteTimer.set[uint8_t id](tos_time_t in) {
    if ( id>=MAX_NUM_TIMERS ) {
      dbg(DBG_TIME, "Atimer.set: Invalid id=\%d max=%d\n", id, MAX_NUM_TIMERS);
      return FAIL;
    }

    if (call TimeUtil.compare(call Time.get(), in) > 0)
      {
	dbg(DBG_TIME, "Atimer.set: time has passed\n");
	//signal AbsoluteTimer.fired[id]();
	return FAIL;
      }
    aTimer[id] = in;
    // dbg(DBG_TIME, "Atimer.set: baseTimerIndex =\%d \n", baseTimerIndex);
    return SUCCESS;
  }


  command result_t AbsoluteTimer.cancel[uint8_t id]() {
    if (id >= MAX_NUM_TIMERS || (aTimer[id].high32 == 0 && aTimer[id].low32 == 0))
      return FAIL;
    aTimer[id].high32 = 0;
    aTimer[id].low32 = 0;
    return SUCCESS;
  }

  default event result_t AbsoluteTimer.fired[uint8_t id]() {
    return SUCCESS ;
  }

  event result_t Timer.fired() {
    uint8_t i;

    atomic time = call TimeUtil.addUint32(time, interval);
    // The i-1 hack gets rid of a gcc warning when we have no AbsoluteTimers
    for (i = 1; i <= MAX_NUM_TIMERS; i++)
      if ((aTimer[i - 1].low32 || aTimer[i - 1].high32) &&
	  call TimeUtil.compare(time, aTimer[i - 1]) >= 0)
	{
	  aTimer[i - 1].high32 = 0;
	  aTimer[i - 1].low32 = 0;
	  signal AbsoluteTimer.fired[i - 1]();
	}
    atomic {
      if (timingChanged) {
	timingChanged = FALSE;
	call Timer.stop();
	call Timer.start(TIMER_REPEAT, interval);
      }
    }
    return SUCCESS;
  }

  /**
   *  Set the 64 bits logical time to a specified value 
   *  @param t Time in the unit of binary milliseconds
   *           type is tos_time_t
   *  @return none
   */
  command void TimeSet.set(tos_time_t t) {
    tos_time_t change = call TimeUtil.subtract(t, time);
    uint8_t i;

    atomic {
      time = t;
    }

    /* Adjust all timers to be the same time in the future
       (avoids big surprises when setting the time way in the past...) */
    for (i = 0; i < MAX_NUM_TIMERS; i++)
      if (aTimer[i].low32 || aTimer[i].high32)
	aTimer[i] = call TimeUtil.add(aTimer[i], change);
  }


  /**
   *  Adjust logical time by n  binary milliseconds.
   *
   *  @param us unsigned 16 bit interger 
   *            positive number advances the logical time 
   *            negtive argument regress the time 
   *            This operation will not take effect immidiately
   *            The adjustment is done duing next clock.fire event
   *            handling.
   *  @return none
   */
  command void TimeSet.adjust(int16_t n) {
    call TimeSet.adjustNow(n);
  }

  /**
   *  Adjust logical time by x milliseconds.
   *
   *  @param x  32 bit interger
   *            positive number advances the logical time
   *            negtive argument regress the time
   *  @return none
   */
  command void TimeSet.adjustNow(int32_t x) {
    call TimeSet.set(call TimeUtil.addint32(time, x));
  }

}
