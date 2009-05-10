// $Id: TupleRouter.nc,v 1.28 2005/08/14 19:37:59 smadden Exp $

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


includes AM;
includes SchemaType;
includes Attr;
includes DBBuffer;
#ifdef kSUPPORTS_EVENTS
includes Event;
#endif

#ifndef NETWORK_MODULE
#define NETWORK_MODULE	NetworkC
#endif

configuration TupleRouter {
  provides interface QueryProcessor;
  provides interface StdControl;
#ifdef HSN_ROUTING
  provides interface HSNValue;
#endif
}

#ifdef PLATFORM_PC
#undef TIMESYNC
#else
#undef TIMESYNC
#endif

implementation {
  components NETWORK_MODULE, Tuple, Query, ParsedQuery, 
	SelOperator, QueryResult, TupleRouterM, TinyAlloc,
	AggOperatorConf,
    LogicalTime, RandomLFSR, 
	PotC, 
#ifdef LEDS_ON
	LedsC,
#else
	NoLeds as LedsC, 
#endif
#ifdef USE_WATCHDOG
	WDTC,
#endif
	TinyDBAttr,
    DBBufferC, TinyDBCommand, Attr, ExprEvalC, Command, TableM, 
    ServiceSchedulerC, HPLPowerManagementM, SimpleTimeM, TimerC
#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT) || defined(PLATFORM_CRICKET)
    , CC1000RadioIntM as Radio
#endif
#ifdef kSUPPORTS_EVENTS
	, TinyDBEvent 
#endif
#ifdef kUART_DEBUGGER
	, UartDebuggerM, UART
#endif
#ifdef kMATCHBOX
    , Matchbox, NoDebug
#endif
#ifdef TIMESYNC
    , TimeSyncC
#endif
    ;

  TupleRouterM.QueryProcessor = QueryProcessor;
  TupleRouterM.StdControl = StdControl;
  TupleRouterM.Network -> NETWORK_MODULE;
  TupleRouterM.NetControl -> NETWORK_MODULE;
  TupleRouterM.AttrUse -> TinyDBAttr;
  TupleRouterM.TupleIntf -> Tuple;
  TupleRouterM.QueryIntf -> Query;
  TupleRouterM.ParsedQueryIntf -> ParsedQuery;
  TupleRouterM.SelOperator -> SelOperator;
  TupleRouterM.AggOperator -> AggOperatorConf;
  TupleRouterM.QueryResultIntf -> QueryResult;
  TupleRouterM.MemAlloc -> TinyAlloc;
  TupleRouterM.AbsoluteTimer -> LogicalTime.AbsoluteTimer[unique("AbsoluteTimer")];
//  TupleRouterM.MyTimer -> TimerC.Timer[unique("Timer")];
  TupleRouterM.TimeSet -> LogicalTime;
  TupleRouterM.TimeUtil -> LogicalTime;
  TupleRouterM.Leds -> LedsC;
  TupleRouterM.TimerControl -> LogicalTime.StdControl;
#ifdef TIMESYNC
  TupleRouterM.TimerControl -> TimeSyncC.StdControl;
#endif
  //  TupleRouterM.TimerControl -> LogicalTime.StdControl;
  // TupleRouterM.ChildControl -> NETWORK_MODULE.StdControl;
  TupleRouterM.AttrControl -> TinyDBAttr.StdControl;
  TupleRouterM.ChildControl -> TinyDBAttr.StdControl;
  TupleRouterM.ChildControl -> TinyDBCommand.StdControl;
  TupleRouterM.ChildControl -> DBBufferC.StdControl;
  TupleRouterM.Time -> LogicalTime;
#ifdef kSUPPORTS_EVENTS
  TupleRouterM.ChildControl -> TinyDBEvent.StdControl;
#endif
  TupleRouterM.ChildControl -> ServiceSchedulerC.SchedulerClt;
#ifdef kMATCHBOX
  TupleRouterM.ChildControl -> Matchbox.StdControl;
#endif
#ifdef kUART_DEBUGGER
  TupleRouterM.UartDebuggerControl -> UartDebuggerM.StdControl;
#endif

  TupleRouterM.DBBuffer -> DBBufferC;
  TupleRouterM.CommandUse -> TinyDBCommand;
#ifdef kSUPPORTS_EVENTS
  TupleRouterM.EventUse -> TinyDBEvent;
#endif

  TupleRouterM.addResults -> AggOperatorConf.addResults;
#ifdef kSUPPORTS_EVENTS
  TupleRouterM.EventFiredCommand -> Command.Cmd[unique("Command")];
#endif
#ifdef kLIFE_CMD
  TupleRouterM.SetLifetimeCommand -> Command.Cmd[unique("Command")];
#endif
  TupleRouterM.NetworkMonitor -> NETWORK_MODULE;
#ifdef HAS_ROUTECONTROL
  TupleRouterM.RouteControl -> NETWORK_MODULE;
#endif
  TupleRouterM.Table -> TableM;
  TupleRouterM.ServiceScheduler -> ServiceSchedulerC;
  TupleRouterM.Random -> RandomLFSR;
  TupleRouterM.setSimpleTimeInterval -> SimpleTimeM.setInterval;
  TupleRouterM.getSimpleTimeInterval -> SimpleTimeM.getInterval;


#ifdef kUART_DEBUGGER
  TupleRouterM.UartDebugger -> UartDebuggerM;
  DBBufferC.UartDebugger -> UartDebuggerM;
  ParsedQuery.UartDebugger -> UartDebuggerM;
  Tuple.UartDebugger -> UartDebuggerM;
  TableM.UartDebugger -> UartDebuggerM;
#endif

#ifdef HSN_ROUTING
  TupleRouterM.HSNValue = HSNValue;
  TupleRouterM.HSNValue <- NETWORK_MODULE;
#endif

  ParsedQuery.AttrUse -> TinyDBAttr;
  ParsedQuery.QueryResultIntf -> QueryResult;
  ParsedQuery.TupleIntf -> Tuple;
  ParsedQuery.AggOperator -> AggOperatorConf;
  ParsedQuery.finalizeAggExpr -> AggOperatorConf.finalizeAggExpr;
  ParsedQuery.Leds -> LedsC;
  ParsedQuery.getGroupNoFromQr -> AggOperatorConf.getGroupNoFromQr;
  ParsedQuery.Table -> TableM;
  ParsedQuery.DBBuffer -> DBBufferC;


  DBBufferC.RadioQueue -> TupleRouterM;
  DBBufferC.MemAlloc -> TinyAlloc;
  DBBufferC.QueryProcessor->TupleRouterM;
  DBBufferC.Leds -> LedsC;
  DBBufferC.CommandUse -> TinyDBCommand;
  DBBufferC.QueryResultIntf -> QueryResult;
  DBBufferC.ParsedQueryIntf -> ParsedQuery;
  DBBufferC.TupleIntf -> Tuple;
  DBBufferC.allocDebug -> TinyAlloc.allocDebug;
  DBBufferC.AttrUse -> TinyDBAttr;
#ifdef kMATCHBOX
  DBBufferC.FileWrite -> Matchbox.FileWrite[unique("FileWrite")];
  DBBufferC.FileRead -> Matchbox.FileRead[unique("FileRead")];

  DBBufferC.HeaderFileWrite -> Matchbox.FileWrite[unique("FileWrite")];
  DBBufferC.HeaderFileRead -> Matchbox.FileRead[unique("FileRead")];

  DBBufferC.FileRename -> Matchbox;
  DBBufferC.FileDelete -> Matchbox;
  DBBufferC.FileDir -> Matchbox;

  Matchbox.ready -> DBBufferC.fsReady;

  Matchbox.Debug -> NoDebug;


#endif

/*
  AggOperator.QueryProcessor -> TupleRouterM;
  AggOperator.TupleIntf -> Tuple;
  AggOperator.ParsedQueryIntf -> ParsedQuery;
  AggOperator.MemAlloc ->TinyAlloc;
  AggOperator.signalError -> TupleRouterM.signalError;
  AggOperator.ExprEval -> ExprEvalC;
  AggOperator.QueryResultIntf -> QueryResult;
  AggOperator.Leds -> LedsC;
*/
  
  SelOperator.TupleIntf -> Tuple;
  SelOperator.ExprEval -> ExprEvalC;

  Tuple.ParsedQueryIntf -> ParsedQuery;
  Tuple.AttrUse -> TinyDBAttr;
  Tuple.QueryProcessor -> TupleRouterM;
  Tuple.CatalogTable -> DBBufferC;
  Tuple.Table -> TableM;
  Tuple.DBBuffer -> DBBufferC;


  QueryResult.TupleIntf -> Tuple;
  QueryResult.MemAlloc -> TinyAlloc;
  QueryResult.Leds -> LedsC;

  TableM.MemAlloc -> TinyAlloc;
  
  TinyAlloc.Leds -> LedsC;
  TinyAlloc.StdControl = StdControl;

#ifdef kUART_DEBUGGER
  UartDebuggerM.UART -> UART;
#endif
  ServiceSchedulerC.StdControl[kTINYDB_SERVICE_ID] -> TupleRouterM.StdControl;

#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT)  || defined(PLATFORM_CRICKET)
  TupleRouterM.RadioSendCoordinator->Radio.RadioSendCoordinator;
  TupleRouterM.RadioReceiveCoordinator->Radio.RadioReceiveCoordinator;

  TupleRouterM.PowerMgmtEnable -> HPLPowerManagementM.Enable;
  TupleRouterM.PowerMgmtDisable -> HPLPowerManagementM.Disable;
#endif

#ifdef USE_WATCHDOG
  TupleRouterM.PoochHandler -> WDTC.StdControl;
  TupleRouterM.WDT -> WDTC;
#endif
}
