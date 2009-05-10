// $Id: WinRandM.nc,v 1.4 2003/10/07 21:46:22 idgay Exp $

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
 * Implements WINRAND aggregate
 *
 */
includes Aggregates;
//includes TinyDB;

module WinRandM {
	provides {
		interface Aggregate;
	}
	
	uses {
		interface Random;
	}
}

implementation {

	typedef struct {
		int16_t value;
		uint8_t chosen;
		uint8_t current;
	} RandData;
	
	typedef struct {
		RandData lastResult;
		
		uint8_t	head;
		uint8_t tail;
		uint8_t size;
		uint8_t nvals;
		
		uint8_t epochsLeft;
		
		uint8_t value[1];//variable number of data readings
	} TemporalRandData;
	
	void addData(TemporalRandData *tad, int16_t value);

	command result_t Aggregate.merge(char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues) {
		TemporalRandData *dest  = (TemporalRandData *)destdata;
		TemporalRandData *merge = (TemporalRandData *)mergedata;
		
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		if (call Random.rand() & 0x00000001 == 0) {
			dest->lastResult.value = merge->lastResult.value;
			dest->lastResult.chosen = merge->lastResult.chosen;
		}
		
		if (epochsPerWindow > slidingDist) {
			uint16_t i,n;
			for (i=dest->head, n=0; n < dest->nvals; i=(i+1) % dest->size, n++) {
				if (call Random.rand() & 0x00000001 == 0)
					dest->value[i] = merge->value[i];
			}
		}
		
		return SUCCESS;
	}
	
	//we'll probably get rid of this later
	command result_t Aggregate.update(char *destdata, char* value, ParamList *params, ParamVals *paramValues) {
		TemporalRandData *dest  = (TemporalRandData *)destdata;
		int16_t val = *(int16_t *)value;
		
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		if (dest->lastResult.current == dest->lastResult.chosen)
			dest->lastResult.value = val;
		dest->lastResult.current++;
		
		if (epochsPerWindow > slidingDist) addData(dest, val);
		
		return SUCCESS;
	}

	//doubles as startEpoch right now? might separate the two
	command result_t Aggregate.init(char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime){
		TemporalRandData *mydata  = (TemporalRandData *)data;
		
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		if (mydata->epochsLeft == 0 || isFirstTime) {
			mydata->lastResult.value = 0;
			mydata->lastResult.current = 0;
			mydata->lastResult.chosen = call Random.rand() % epochsPerWindow;
			mydata->epochsLeft = slidingDist;
			
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
					if (mydata->lastResult.current == mydata->lastResult.chosen)
						mydata->lastResult.value = mydata->value[i];
					mydata->lastResult.current++;
				}
			}
		}
		
		return SUCCESS;
	}

	command uint16_t Aggregate.stateSize(ParamList *params, ParamVals *paramValues) {
		uint8_t epochsPerWindow = getEpochsPerWindow(paramValues);
		uint8_t slidingDist     = getSlidingDist(paramValues);
		
		TemporalRandData r;
		uint16_t size = sizeof(r);
		
		if (epochsPerWindow > slidingDist)
		  size = size - sizeof(r.value) + (epochsPerWindow - slidingDist) * sizeof(r.value[0]);
		  
		return size;
	}

	command bool Aggregate.hasData(char *data, ParamList *params, ParamVals *paramValues) {
		TemporalRandData *mydata  = (TemporalRandData *)data;
		
		if (getEpochsPerWindow(paramValues) > 0 && mydata->epochsLeft > 0)
		 	mydata->epochsLeft--;
		if (mydata->epochsLeft == 0)	return TRUE;
		else return FALSE;
	}

	command TinyDBError Aggregate.finalize(char *data, char *result_buf, ParamList *params, ParamVals *paramValues) {
		TemporalRandData *mydata  = (TemporalRandData *)data;
		*(int16_t *)result_buf = mydata->lastResult.value;
		return err_NoError;
	}
	
	void addData(TemporalRandData *tad, int16_t value) {
		tad->value[tad->tail] = value;
		tad->tail = (tad->tail + 1) % tad->size;
		if (tad->nvals == tad->size)
			tad->head = (tad->head + 1) % tad->size;
		else
			tad->nvals++;
	}
	
	command AggregateProperties Aggregate.getProperties() {
		return 0;
	}
	
	
}
