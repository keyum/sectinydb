// $Id: CompileDefines.h,v 1.23 2005/08/14 19:37:31 smadden Exp $

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
#ifndef __COMPILE_DEFINES__
#define __COMPILE_DEFINES__

//defines indicating which features are in use
#undef kUSE_MAGNETOMETER //include magnetometer attribute? 1596 bytes code, 55 bytes ram
#define kQUERY_SHARING //allow query sharing
#undef kFANCY_AGGS //use fancy aggregates
#undef kEEPROM_ATTR //enable the EEPROM attribute -- uses about 3 kb of code
#undef kCONTENT_ATTR //enable the contention attribute
#undef kRAW_MIC_ATTRS // enable raw microphone or tone detector attributes
#undef kGROUP_ATTR
#undef kQUEUE_LEN_ATTR
#undef kMHQUEUE_LEN_ATTR
#undef kLIFE_CMD
#undef kSUPPORTS_EVENTS //about 3k of code, 100 bytes of ram for event based queries
#define kSTATUS //200 bytes of code -- allow lists of running queries to be fetched over the UART
#define kHAS_NEIGHBOR_ATTR //allows fetching of neighbor bitmap
#if !defined(PLATFORM_PC)
# undef kMATCHBOX //enabled logging to EEPROM, 20k code, 489 bytes RAM
# undef kUART_DEBUGGER //allow output to a UART debugger
#endif


/*            RAM     CODE
   MAG        55      1596
   SHARING
   AGGS
   EEPROM              ~3k
   UART       68       1684
   EVENTS     100      ~3k
   STATUS              ~200
 */

//Probably don't want to mess with the options below -- 
// they control parameters that are set byt he options above

#ifdef kMATCHBOX
//matchbox needs an extra buffer
# define NUMBUFFERS 3 //how many buffers does BufferC need / have?
//needs extra RAM, so allocate less to the multihop queue
# define MHOP_QUEUE_SIZE 4 
#else
# define NUMBUFFERS 2 //how many buffers does BufferC need / have?
# define MHOP_QUEUE_SIZE 6
#endif

#define SEND_QUEUE_SIZE (MHOP_QUEUE_SIZE + 2)

#define NETWORK_MULTIHOP 0
#define NETWORK_HSN		 1

//define HSN_ROUTING for HSN network
//#define HSN_ROUTING

#ifdef HSN_ROUTING
#define NETWORK_MODULE	TinyDBShim
#define NETWORK_MODULE_ID NETWORK_HSN
#endif

#ifndef NETWORK_MODULE
# define NETWORK_MODULE_ID NETWORK_MULTIHOP
# define NETWORK_MODULE NetworkMultiHop 
#endif

#if NETWORK_MODULE_ID==NETWORK_MULTIHOP
#  define HAS_ROUTECONTROL
#endif

#ifdef GENERICCOMM
# undef GENERICCOMM
#endif

#define GENERICCOMM GenericCommPromiscuous

#ifndef MULTIHOPROUTER
#define MULTIHOPROUTER	WMEWMAMultiHopRouter
#endif

// #define USE_LOW_POWER_LISTENING

#define MAX_NUM_SERVICES 2 
#define LogicalTime SimpleTime
#define MH6_ROUTING

#ifndef PLATFORM_MICA2DOT
#define LEDS_ON
#endif

#define MS_PER_CLOCK_EVENT	256

#ifndef PLATFORM_PC
#undef USE_WATCHDOG
#define LOG_TUPLES
#endif

#endif
