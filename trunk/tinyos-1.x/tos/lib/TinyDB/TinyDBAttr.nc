// $Id: TinyDBAttr.nc,v 1.23 2004/07/16 21:31:28 ammbot Exp $

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
includes Attr;

configuration TinyDBAttr {
  provides interface AttrUse;
  provides interface StdControl;
}

implementation {
  components Attr, AttrPot, AttrGlobal, TinyDBAttrM, TupleRouterM, AttrTime,
  TinyAlloc, NETWORK_MODULE
#ifdef kEEPROM_ATTR
, AttrLog
#endif
#if !defined(PLATFORM_PC)
, AttrVoltage
#endif
#if defined(BOARD_MICASB)
, AttrTemp, AttrPhoto
#if !defined(PLATFORM_PC)
    , AttrAccel
# ifdef kUSE_MAGNETOMETER
    , AttrMag
# endif
    , AttrMic
#endif
#endif /* BOARD_MICASB */
#if defined(BOARD_MICAWB) || defined(BOARD_MICAWBDOT)
	, AttrHumidity, AttrTaosPhoto, AttrPressure
#ifdef BOARD_MICAWBDOT
    //, AttrHamamaTsu , AttrMelexis
#endif
#endif /* BOARD_MICAWB */
#if defined(BOARD_MICAWBDOT)
	, AttrHamamaTsu 
#endif /* BOARD_MICAWBDOT */

//
//#ifdef BOARD_MDA300CA
//       , AttrEcho10, AttrHumidity
//#endif


#ifdef BOARD_MDA300CA
       , AttrKTypeTC, AttrHumidity
#endif

#ifdef BOARD_MEP500
       , AttrHumidity
#endif

#ifdef BOARD_MEP401
       , AttrHumidity
       , AttrIntHumidity
       , AttrPressure
       , AttrHama
       , AttrNewAccel
#endif
    ;
  AttrUse = Attr.AttrUse;

  AttrGlobal.StdControl = StdControl;
  AttrPot.StdControl = StdControl;
  AttrTime.StdControl = StdControl;
#ifdef kEEPROM_ATTR
  AttrLog.StdControl = StdControl;
#endif
  TinyDBAttrM.StdControl = StdControl;
#if !defined(PLATFORM_PC)
  AttrVoltage.StdControl = StdControl;
#endif

#ifdef BOARD_MICASB
  AttrPhoto.StdControl = StdControl;
  AttrTemp.StdControl = StdControl;
#if !defined(PLATFORM_PC)
  AttrAccel.StdControl = StdControl;
#ifdef kUSE_MAGNETOMETER
  AttrMag.StdControl = StdControl;
#endif
  AttrMic.StdControl = StdControl;
#endif
#endif /* BOARD_MICASB */
#if defined(BOARD_MICAWB) || defined(BOARD_MICAWBDOT)
  AttrHumidity.StdControl = StdControl;
  AttrTaosPhoto.StdControl = StdControl;
  AttrPressure.StdControl = StdControl;
  // AttrMelexis.StdControl = StdControl;
#endif
#if defined(BOARD_MICAWBDOT)
  AttrHamamaTsu.StdControl = StdControl;
#endif /* BOARD_MICAWBDOT*/

//#ifdef BOARD_MDA300CA
//  AttrEcho10.StdControl = StdControl;
//  AttrHumidity.StdControl = StdControl;
//#endif

#ifdef BOARD_MDA300CA
  AttrKTypeTC.StdControl = StdControl;
  AttrHumidity.StdControl = StdControl;
#endif

#ifdef BOARD_MEP500 
  AttrHumidity.StdControl = StdControl;
#endif




#ifdef BOARD_MEP401
// External sensirion humidity and temperature sensor
  AttrHumidity.StdControl = StdControl;

// Internal sensirion humidity and temperature sensor 
  AttrIntHumidity.StdControl = StdControl;

// Intersema pressure and temperature sensor
  AttrPressure.StdControl = StdControl;

// Hamamatsu Photodiodes (top,bot) x (par,bs)
  AttrHama.StdControl = StdControl;

// 2-D Accelerometer
  AttrNewAccel.StdControl = StdControl;
#endif




  TinyDBAttrM.ParentAttr -> Attr.Attr[unique("Attr")];
#ifdef kCONTENT_ATTR
  TinyDBAttrM.ContentionAttr -> Attr.Attr[unique("Attr")];
#endif
  TinyDBAttrM.FreeSpaceAttr -> Attr.Attr[unique("Attr")];
#ifdef kQUEUE_LEN_ATTR
  TinyDBAttrM.QueueLenAttr -> Attr.Attr[unique("Attr")];
#endif
#ifdef kMHQUEUE_LEN_ATTR
  TinyDBAttrM.MHQueueLenAttr -> Attr.Attr[unique("Attr")];
#endif
  TinyDBAttrM.DepthAttr -> Attr.Attr[unique("Attr")];
  TinyDBAttrM.QidAttr -> Attr.Attr[unique("Attr")];
  // TinyDBAttrM.XmitCountAttr -> Attr.Attr[unique("Attr")];
  TinyDBAttrM.QualityAttr -> Attr.Attr[unique("Attr")];
#ifdef kHAS_NEIGHBOR_ATTR
  TinyDBAttrM.NeighborAttr -> Attr.Attr[unique("Attr")];
#endif
  TinyDBAttrM.QueryProcessor -> TupleRouterM;
  TinyDBAttrM.NetworkMonitor -> NETWORK_MODULE;
  TinyDBAttrM.MemAlloc -> TinyAlloc;
}
