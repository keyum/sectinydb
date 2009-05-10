// $Id: AggOperatorConf.nc,v 1.5 2003/10/07 21:46:20 idgay Exp $

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
/**
 * This configuration wires AggOperator to individual aggregates
 */
 
#ifndef NETWORK_MODULE
#define NETWORK_MODULE	NetworkC
#endif

includes Aggregates;

configuration AggOperatorConf {

provides {
    interface Operator;
    command TinyDBError addResults(QueryResult *qr, ParsedQuery *q, Expr *e);
    command TinyDBError finalizeAggExpr(QueryResult *qr, ParsedQueryPtr q, Expr *e, char *result_buf);
    command short getGroupNoFromQr(QueryResult *qr);
  }
}

implementation {
	components AggOperator, TinyAlloc, TupleRouterM, Tuple, ParsedQuery, ExprEvalC,
			   NoLeds, QueryResult;
	components AggregateUseM, MaxM, MinM, CountM, SumM, AvgM, ExpAvgM,
			   WinMinM, WinMaxM, WinCountM, WinSumM, WinAvgM;
#ifdef kFANCY_AGGS
	components WinRandM, AdpDeltaM, DeltaM, TrendM, RandomLFSR, NETWORK_MODULE;
#endif
			   
	Operator = AggOperator;
	addResults = AggOperator.addResults;
	finalizeAggExpr = AggOperator.finalizeAggExpr;
	getGroupNoFromQr = AggOperator.getGroupNoFromQr;
	
	AggOperator.MemAlloc -> TinyAlloc;
	AggOperator.QueryProcessor -> TupleRouterM;
	AggOperator.TupleIntf -> Tuple;
 	AggOperator.ParsedQueryIntf -> ParsedQuery;
	AggOperator.ExprEval -> ExprEvalC;
	AggOperator.Leds -> NoLeds;
	AggOperator.QueryResultIntf -> QueryResult;
	AggOperator.signalError -> TupleRouterM.signalError;
	
	//hook up aggregates
	AggOperator.AggregateUse -> AggregateUseM;
	
	//maybe we need a config for AggregateUse?
    MaxM.Aggregate <- AggregateUseM.Agg[kMAX];
    MinM.Aggregate <- AggregateUseM.Agg[kMIN];
    CountM.Aggregate <- AggregateUseM.Agg[kCOUNT];
    SumM.Aggregate <- AggregateUseM.Agg[kSUM];
    AvgM.Aggregate <- AggregateUseM.Agg[kAVG];
    ExpAvgM.Aggregate <- AggregateUseM.Agg[kEXP_AVG];
    WinMinM.Aggregate <- AggregateUseM.Agg[kWIN_MIN];
    WinMaxM.Aggregate <- AggregateUseM.Agg[kWIN_MAX];
    WinCountM.Aggregate <- AggregateUseM.Agg[kWIN_COUNT];
    WinSumM.Aggregate <- AggregateUseM.Agg[kWIN_SUM];
    WinAvgM.Aggregate <- AggregateUseM.Agg[kWIN_AVG];
#ifdef kFANCY_AGGS
	WinRandM.Aggregate <- AggregateUseM.Agg[kWIN_RAND];
	AdpDeltaM.Aggregate <- AggregateUseM.Agg[kADP_DELTA];
	DeltaM.Aggregate <- AggregateUseM.Agg[kDELTA];
	TrendM.Aggregate <- AggregateUseM.Agg[kTREND];
	
    WinRandM.Random -> RandomLFSR;
	AdpDeltaM.NetworkMonitor -> NETWORK_MODULE;
#endif

}
	
