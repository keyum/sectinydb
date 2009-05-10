// $Id: WinCountM.nc,v 1.4 2003/10/07 21:46:22 idgay Exp $

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
 * Implements WINCOUNT aggregate
 *
 * Author:	Eugene Shvets
 * @author Eugene Shvets
 */
includes Aggregates;
//includes TinyDB;

module WinCountM {
	provides {
		interface Aggregate;
	}
}

implementation {

	command result_t Aggregate.merge(char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues) {
		TemporalAlgebraicData *dest  = (TemporalAlgebraicData *)destdata;
		TemporalAlgebraicData *merge = (TemporalAlgebraicData *)mergedata;
		
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		dest->lastResult.value += merge->lastResult.value;
		
		if (epochsPerWindow > slidingDist) {
			uint16_t i,n;
			for (i=dest->head, n=0; n < dest->nvals; i=(i+1) % dest->size, n++)
				dest->value[i] += merge->value[i];
		}
		
		return SUCCESS;
	}
	
	//we'll probably get rid of this later
	command result_t Aggregate.update(char *destdata, char* value, ParamList *params, ParamVals *paramValues) {
		TemporalAlgebraicData *dest  = (TemporalAlgebraicData *)destdata;
		
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		dest->lastResult.value++;
		
		if (epochsPerWindow > slidingDist) addValueToTemporalAggState(dest,1);
		
		return SUCCESS;
	
	}

	//doubles as startEpoch right now? might separate the two
	command result_t Aggregate.init(char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime){
		TemporalAlgebraicData *mydata  = (TemporalAlgebraicData *)data;
		
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		if (mydata->epochsLeft == 0 || isFirstTime) {
			mydata->epochsLeft = slidingDist;
			mydata->lastResult.value = 0;
			
			if (isFirstTime && epochsPerWindow > slidingDist) {
				//very first time
				mydata->head = mydata->tail = 0;
				mydata->size = epochsPerWindow - slidingDist;
				mydata->nvals = 0;
			}
		
			if (epochsPerWindow > slidingDist) {
				// aggregate the remaining data from last window
				uint16_t i,n;
				for (i=mydata->head, n = 0; n < mydata->nvals; i=(i+1) % mydata->size, n++) {
						mydata->lastResult.value += mydata->value[i];
				}
			}
		}
		
		return SUCCESS;
	}

	command uint16_t Aggregate.stateSize(ParamList *params, ParamVals *paramValues) {
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		TemporalAlgebraicData tad;
		uint16_t size = sizeof(tad);
		
		if (epochsPerWindow > slidingDist)
		  size = size - sizeof(tad.value) + (epochsPerWindow - slidingDist) * sizeof(tad.value[0]);
		  
		return size;
	}

	command bool Aggregate.hasData(char *data, ParamList *params, ParamVals *paramValues) {
		TemporalAlgebraicData *mydata  = (TemporalAlgebraicData *)data;
		
		if (getEpochsPerWindow(paramValues) > 0 && mydata->epochsLeft > 0)
		 	mydata->epochsLeft--;
		if (mydata->epochsLeft == 0)	return TRUE;
		else return FALSE;
	}

	command TinyDBError Aggregate.finalize(char *data, char *result_buf, ParamList *params, ParamVals *paramValues) {
		TemporalAlgebraicData *mydata  = (TemporalAlgebraicData *)data;
		*(int16_t *)result_buf = mydata->lastResult.value;
		return err_NoError;
	}
	
	command AggregateProperties Aggregate.getProperties() {
		return 0;
	}
	
	
}
