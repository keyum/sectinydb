// $Id: Aggregates.h,v 1.6 2003/10/07 21:46:22 idgay Exp $

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
#ifndef __AGGREGATES_H__
#define __AGGREGATES_H__

#define kDEBUG_AGGS

enum {
	kMAX_SHORT = 0x7FFF,
    kMIN_SHORT = 0x8000
};

typedef enum {
  kNOOP = 0,
  kSUM = 1,
  kMIN = 2,
  kMAX = 3,
  kCOUNT = 4,
  kAVG = 5,
  kEXP_AVG = 6,
  kWIN_AVG = 7,
  kWIN_SUM = 8,
  kWIN_MIN = 9,
  kWIN_MAX = 10,
  kWIN_COUNT = 11,
  kDELTA = 12,
  kTREND = 13,
  kWIN_RAND = 14,
  kADP_DELTA = 15,
} AggregateID;


typedef struct {
	int16_t value;//2
	int16_t id;//4
} AlgebraicData;

typedef struct {
  	AlgebraicData lastResult;//4
  	
  	uint8_t	head;//5
	uint8_t tail;//6
	uint8_t size;//7
	uint8_t nvals;//8
	
	uint8_t epochsLeft;//9
	
	uint8_t value[1];//variable number of data readings
} TemporalAlgebraicData;

typedef struct {
	int16_t sum;
	uint16_t count;
} AverageData;

// NOTE: Following 3 structs should be in AdpDeltaM.nc,
// but AggOperator needs to handle AdpDelta specially in one place (BAD thing)
typedef struct {
		int16_t value;
		uint16_t epoch;
		uint8_t curInd;//5
	} AdpDeltaData;
	
	typedef struct {
		int16_t value;
		uint16_t epoch;//4
	} AdpAggData;
	
	typedef struct {
		AdpDeltaData lastResult;//5
		
		uint8_t	head;
		uint8_t tail;
		uint8_t size;
		uint8_t nvals;
		
		uint8_t epochsLeft;//10
		
		AdpAggData value[1];//variable number of data readings
	} TemporalAdpDeltaData;

/*
typedef struct {
	int16_t id;
	int16_t value;
} fieldRecord;

typedef struct {
	fieldRecord record[3];
} Min3Data;
*/


/**************************************
 * Aggregate properties
 **************************************/
 
typedef enum {
		   kEXEMPLARY_PROPERTY = 0x1,
		   kMONOTONIC_PROPERTY = 0x2,
		   kDUPLICATE_INSENSITIVE_PROPERTY = 0x4 // by default things are dupl sensitive
} AggregateProperties;
	
bool isExemplary(AggregateProperties ap) {
	return (ap & kEXEMPLARY_PROPERTY);
}

bool isMonotonic(AggregateProperties ap) {
	return (ap & kMONOTONIC_PROPERTY);
}


/*************************************************************
 * HAndling parameters to aggregates
 ************************************************************/

void setParamValues(ParamVals *v, Expr *e) {
	v->numParams = 4;
	v->paramDataPtr[0] = (char *) &(e->ex.tagg.args[0]);
	v->paramDataPtr[1] = (char *) &(e->ex.tagg.args[1]);
	v->paramDataPtr[2] = (char *) &(e->ex.tagg.args[2]);
	//last spot intentionally left empty
}

/**
 * Following enum describes the semantics of arguments stored in
 * TemporalAggExpr.args array and in ParamVals structure.
 */
typedef enum {
	kEPOCHS_PER_WINDOW    = 0, // all but EXP_AVG
	kNEW_BITS_PER_SAMPLE  = 0, // EXP_AVG
	kSLIDING_DIST         = 1, // all but TREND, ADPDELTA
	kTREND_THRESHOLD      = 1, // TREND
	kCONTENTION_THRESHOLD = 1, // ADPDELTA (30 as typical value)
	kDELTA_THRESHOLD      = 2, // DELTA, TREND. NOTE: needs set up
	kCURRENT_EPOCH        = 2 // ADPDELTA. is not part of user interface. NOTE: needs set up NOTE: it's a uint16_t !
	
} ParamIndex;

/**
 * Convenince routines for access to arguments packaged into ParamVals
 */
uint8_t getEpochsPerWindow(ParamVals *v) {
	return *(uint8_t *)(v->paramDataPtr[kEPOCHS_PER_WINDOW]);
}

uint8_t getSlidingDist(ParamVals *v) {
	return *(uint8_t *)(v->paramDataPtr[kSLIDING_DIST]);
}

uint8_t getTrendThreshold(ParamVals *v) {
	return *(uint8_t *)(v->paramDataPtr[kTREND_THRESHOLD]);
}

uint8_t getContentionThreshold(ParamVals *v) {
	return *(uint8_t *)(v->paramDataPtr[kCONTENTION_THRESHOLD]);
}

uint8_t getNewBitsPerSample(ParamVals *v) {
	return *(uint8_t *)(v->paramDataPtr[kNEW_BITS_PER_SAMPLE]);
}

uint8_t getDeltaThreshold(ParamVals *v) {
	return *(uint8_t *)(v->paramDataPtr[kDELTA_THRESHOLD]);
}

/**
 * Needed by TREND, DELTA
 */
void setDeltaThreshold(ParamVals *v, uint8_t deltaThreshold) {
	*v->paramDataPtr[kDELTA_THRESHOLD] = deltaThreshold;
}

/**
 * Danger: writes uint16 into char *. Needed by ADPDELTA
 */
void setCurrentEpoch(ParamVals *v, uint16_t curEpoch) {
	*((uint16_t *)v->paramDataPtr[kCURRENT_EPOCH]) = curEpoch;
}

uint16_t getCurrentEpoch(ParamVals *v) {
	return *(uint16_t *)(v->paramDataPtr[kCURRENT_EPOCH]);
}

/**
 * Utilities for managing Temporal Aggregate states
 */
 
void addValueToTemporalAggState(TemporalAlgebraicData *tad, short value){
	tad->value[tad->tail] = value;
	tad->tail = (tad->tail + 1) % tad->size;
	if (tad->nvals == tad->size)
		tad->head = (tad->head + 1) % tad->size;
	else
		tad->nvals++;
}


/**
 * Utilities for debugging
 */
 
#ifdef kDEBUG_AGGS

void printTempAlgData(TemporalAlgebraicData* tad) {
	dbg(DBG_USR3,"TempAlgData{lr.value=%d lr.id=%d}\n",tad->lastResult.value, tad->lastResult.id);
}

#endif

#endif
