// $Id: ExpAvgM.nc,v 1.4 2003/10/07 21:46:22 idgay Exp $

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
 * Implements EXPAVG aggregate
 *
 */
includes Aggregates;

module ExpAvgM {
	provides {
		interface Aggregate;
	}
}

implementation {

	typedef struct {
		int16_t value;
		uint8_t epochsLeft;
	} ExpAvgData;

	command result_t Aggregate.merge(char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues) {
		ExpAvgData *dest  = (ExpAvgData *)destdata;
		ExpAvgData *merge = (ExpAvgData *)mergedata;
		
		uint8_t newBits = 16 - getNewBitsPerSample(paramValues);

		dest->value = (dest->value - (dest->value >> newBits)) + (merge->value >> newBits);
		
		return SUCCESS;
	}
	
	//we'll probably get rid of this later
	command result_t Aggregate.update(char *destdata, char* value, ParamList *params, ParamVals *paramValues) {
		ExpAvgData *dest  = (ExpAvgData *)destdata;
		int16_t val = *(int16_t *)value;
		uint8_t newBits = 16 - getNewBitsPerSample(paramValues);
		
		dest->value = (dest->value - (dest->value >> newBits)) + (val >> newBits);
		
		return SUCCESS;
	}

	//doubles as startEpoch right now? might separate the two
	command result_t Aggregate.init(char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime){
		ExpAvgData *mydata = (ExpAvgData *)data;
		
		if (isFirstTime) {
			mydata->value = 0;
			mydata->epochsLeft = 0;
		}
		return SUCCESS;
	}

	command uint16_t Aggregate.stateSize(ParamList *params, ParamVals *paramValues) {
		return sizeof(ExpAvgData);
	}

	command bool Aggregate.hasData(char *data, ParamList *params, ParamVals *paramValues) {
		return TRUE;
	}

	command TinyDBError Aggregate.finalize(char *data, char *result_buf, ParamList *params, ParamVals *paramValues) {
		ExpAvgData *mydata = (ExpAvgData *)data;
		*(int16_t *)result_buf = mydata->value;
		
		return err_NoError;
	}
	
	command AggregateProperties Aggregate.getProperties() {
		return 0;
	}
	
	
}
		
