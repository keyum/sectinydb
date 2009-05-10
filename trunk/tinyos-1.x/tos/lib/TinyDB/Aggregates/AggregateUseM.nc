// $Id: AggregateUseM.nc,v 1.5 2003/10/07 21:46:22 idgay Exp $

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
 * Currently, if you want to add a custom aggregate, you have to edit this file,
 * as well as AggOperatorConf.nc
 *
 * Author:	Eugene Shvets
 * @author Eugene Shvets
 */

module AggregateUseM {
	provides {
		interface AggregateUse;
	}
	
	uses { // Aggs are hooked up in AggregateOperatorConf now,
	       // but we probably want to make wiring of aggregates self-contained
		interface Aggregate as Agg[uint8_t id];
    }
}

implementation {

	command result_t AggregateUse.merge(uint8_t id, char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues) {
		return call Agg.merge[id]( destdata, mergedata, params, paramValues);
	}
	
	//we'll probably get rid of this later
	command result_t AggregateUse.update(uint8_t id, char *destdata, char* value, ParamList *params, ParamVals *paramValues) {
		return call Agg.update[id]( destdata, value, params, paramValues);
	}

	//doubles as startEpoch right now? might separate the two
	command result_t AggregateUse.init(uint8_t id, char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime){
		return call Agg.init[id]( data, params, paramValues, isFirstTime);
	}

	command uint16_t AggregateUse.stateSize(uint8_t id, ParamList *params, ParamVals *paramValues) {
		return call Agg.stateSize[id](params,paramValues);
	}

	command bool AggregateUse.hasData(uint8_t id, char *data, ParamList *params, ParamVals *paramValues) {
		return call Agg.hasData[id](data, params, paramValues);
	}

	command TinyDBError AggregateUse.finalize(uint8_t id, char *data, char *result_buf, ParamList *params, ParamVals *paramValues) {
		return call Agg.finalize[id](data, result_buf, params, paramValues);
	}
	
	command AggregateProperties AggregateUse.getProperties(uint8_t id) {
		return call Agg.getProperties[id]();
	}
	
	/**
	 * Default implementation of Aggregate interface for id's that are not wired
	 */
	default command result_t Agg.merge[uint8_t id]
	(char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues) {
		return SUCCESS;
	}
	
	default command result_t Agg.update[uint8_t id]
	(char *destdata, char* value, ParamList *params, ParamVals *paramValues) {
		return SUCCESS;
	}
	
	default command result_t Agg.init[uint8_t id]
	(char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime){
		return SUCCESS;
	}
	
	default command uint16_t Agg.stateSize[uint8_t id]
	(ParamList *params, ParamVals *paramValues) {
		return 0;
	}
	
	default command bool Agg.hasData[uint8_t id]
	(char *data, ParamList *params, ParamVals *paramValues) {
		return FALSE;
	}
	
	default command TinyDBError Agg.finalize[uint8_t id]
	(char *data, char *result_buf, ParamList *params, ParamVals *paramValues) {
		return err_NoError;
	}
	
	default command AggregateProperties Agg.getProperties[uint8_t id]() {
		return 0;
	}
}

