// $Id: AggOperator.nc,v 1.20 2003/11/06 17:23:06 smadden Exp $

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
 * Authors:	Sam Madden
 *              Design by Sam Madden, Wei Hong, and Joe Hellerstein
 * Date last modified:  6/26/02
 *
 *
 */

/**
 * @author Sam Madden
 * @author Design by Sam Madden
 * @author Wei Hong
 * @author and Joe Hellerstein
 */

includes Aggregates;

module AggOperator {
  provides {
    interface Operator;
    command TinyDBError addResults(QueryResult *qr, ParsedQuery *q, Expr *e);
    command TinyDBError finalizeAggExpr(QueryResult *qr, ParsedQueryPtr q, Expr *e, char *result_buf);
    command short getGroupNoFromQr(QueryResult *qr);
  }

  uses {
    interface MemAlloc;
    interface QueryProcessor;
    interface TupleIntf;
    interface ParsedQueryIntf;
    interface ExprEval;
    interface Leds;
    interface QueryResultIntf;
    interface AggregateUse;

    command void signalError(TinyDBError err, int lineNo);
  }
}
implementation {
  
  #define TDB_SIG_ERR(errNo) call signalError((errNo), __LINE__)
  
  typedef struct {
    int numGroups; //how many groups are there
    int groupSize; //how many bytes per group
    char groupData[1];  //data for groups -- depends on type of aggregate -- of size groupSize * numGroups
  } GroupData, *GroupDataPtr, **GroupDataHandle;
  
  typedef struct {
    short groupNo;//2
    union {
      bool empty;
      char exprIdx; //idx of operator that owns us
    } u;//3
    char aggdata[1];//aggregate-dependent data of variable size
    //size of this space returned as part of groupSize() value
  } __attribute__((packed)) GroupRecord;

  typedef void (*GroupDataCallback)(GroupRecord *d);

  GroupDataCallback mCallback;
  ParsedQuery *mCurQuery;
  Expr *mCurExpr;
  QueryResult *mCurResult;
  Tuple *mCurTuple;
  short mCurGroup;
  Handle mAlloced;
  GroupRecord *mGroupRecord;

  enum {
    QUERY_DONE_STATE = 0x1010, //magic code indicating query is done!
  };


  /* -------------------------------- Local prototypes -------------------------------- */
  void getGroupData(ParsedQuery *pq, short groupNo , Expr *e, GroupDataCallback callback);
  void updateGroupForTuple(GroupRecord *d);
  short groupSize(Expr *e);
  void mergeAggregateValues(GroupRecord *dest, GroupRecord *merge, Expr *e);
  void updateAggregateValue(GroupRecord *d, Expr *e, short fieldValue);
  void initAggregateValue(GroupRecord *d, Expr * e, bool isFirstTime);
  void updateGroupForPartialResult(GroupRecord *d);
  bool aggHasData(GroupRecord *gr, Expr *e);
  GroupRecord *findGroup(GroupDataHandle dh, short groupNum);
  GroupRecord *addGroup(GroupDataHandle dh, short groupNum);
  bool removeEmptyGroup(GroupDataHandle dh);
  short getGroupNo(Tuple *t, ParsedQuery *q, Expr *e);
  bool aggEqual(GroupRecord *r1, GroupRecord *r2, Expr *e);
  //void addValToTemporalAggState(TemporalAggState *tas, short value);
  //short	addAdpDeltaDataToTemporalAggState(TemporalAggState *tas, short lastVal, short newVal, uint16_t epoch);
  //void addAvgdataToTemporalAggState(TemporalAggState *tas, short sum, short count);

  task void fireCallback();

/* -------------------------------- Local Routines for getting / setting group records  -------------------------------- */

  GroupRecord *GET_GROUP_DATA(GroupDataHandle dHan,uint8_t n) {
    return (GroupRecord *)&((**dHan).groupData[(n) * (**dHan).groupSize]);
  }

  void SET_GROUP_DATA(GroupDataHandle dHan,uint8_t n,char *dataptr) {
    memcpy(GET_GROUP_DATA(dHan,n), (const char *)(dataptr), (**dHan).groupSize);
  }
  
  void COPY_GROUP_DATA(GroupDataHandle dHan,uint8_t n,char *dest) {
    memcpy((char *)(dest),(const char *)GET_GROUP_DATA(dHan,n), (**dHan).groupSize);
  }


  /* --gr->aggdata------------ Functions -------------------------------- */



    /* Reset the state that this operator stores for the specified expression
       (Called every epoch)
       Operator state is appended to the expression (ick!) , in the opState handle --
         each expression is owned by exactly one operator, which may store state there.
    */



    //Given a query-result from a different node, add the result into
    //the locally computed value for the query.  The locally computed
    //value is stored with the expression.
    command TinyDBError Operator.processPartialResult(QueryResultPtr qr, ParsedQueryPtr qs, ExprPtr e) {
      GroupRecord *gr = (GroupRecord *)qr->d.data;
      
      if (qr->qrType != kAGG_SINGLE_FIELD) return err_InvalidAggregateRecord;

      if (gr->u.exprIdx != e->idx)
	return err_InvalidAggregateRecord; //not for us

      if (e->opState == (OperatorStateHandle)QUERY_DONE_STATE) return err_NoError;
      
      mCurExpr = e;
      mCurQuery = qs;
      mCurResult = qr;
      dbg(DBG_USR3, "AggOperator.processPartialResult: Calling getGroupData\n");
      
      getGroupData(qs,gr->groupNo, e, &updateGroupForPartialResult);
      return err_NoError;
    }

    //check and see if this result represents the evaluation of this expression
    command bool Operator.resultIsForExpr(QueryResultPtr qr, ExprPtr e) {
      GroupRecord *gr = (GroupRecord *)qr->d.data;
      bool result = TRUE;
      if (qr->qrType != kAGG_SINGLE_FIELD) result = FALSE;
      if (gr->u.exprIdx != e->idx) result = FALSE;
      //dbg(DBG_USR3, "resultIsForExpr: %d\n", result);
      return result;
    }

    
  void updateGroupForPartialResult(GroupRecord *d) {
    GroupRecord *gr = (GroupRecord *)((QueryResult *)mCurResult)->d.data;
    
    dbg(DBG_USR3, "updateGroupForPartialResult called\n");
    
    mergeAggregateValues(d,gr,mCurExpr);
    signal Operator.processedResult(mCurResult, mCurQuery, mCurExpr);
  }

  
  
  /* Return the next result to this query.
    
    If there are no more results, return err_NoMoreResults
    
    qr->result_idx should be set to kFIRST_RESULT if the first result is desired,
    or to the previous value of qr->result_idx returned by the last invocation
    of AGG_OPERATOR_NEXT_RESULT
    
  */
  command TinyDBError Operator.nextResult(QueryResultPtr qr, ParsedQueryPtr qs, ExprPtr e) {
    GroupDataHandle gdh = (GroupDataHandle)e->opState;
    bool empty = TRUE;
    GroupRecord *gr;

    //if (!aggHasData(qr,qs,e)) return err_NoMoreResults;

    if (gdh != NULL) {
      short idx = qr->result_idx;
    
      do {  //loop til we find the next non-empty group
	
	if (idx == kFIRST_RESULT) idx = 0;
	else idx++;
			  
	if (idx >= (**gdh).numGroups) return err_NoMoreResults;
	qr->result_idx = idx;
	qr->qid = qs->qid;
	//just a single field result
	qr->qrType = kAGG_SINGLE_FIELD;
	//copy the data into the buffer
	gr = GET_GROUP_DATA(gdh,idx);
	//TODO: following hasData call is the SOURCE OF INEFFICIENCY
	if (!gr->u.empty && aggHasData(gr,e)) empty = FALSE; //don't output empty results
      } while (empty);

      COPY_GROUP_DATA(gdh,idx,qr->d.data);
      gr = (GroupRecord *)qr->d.data;
      gr->u.exprIdx = e->idx;

    } else
      return err_InvalidAggregateRecord;

    return err_NoError;
  }

  /** Install all of the results for the last epoch of  expression e from pq into qr.
   */
  command TinyDBError addResults(QueryResult *qr, ParsedQuery *pq, ExprPtr e) {
    int i = 0;
    GroupRecord *gr;
    GroupDataHandle gdh = (GroupDataHandle)e->opState;
    TinyDBError err;

    if (gdh == NULL) return err_NoError;
    //if (!aggHasData(qr,pq,e)) return err_NoError;


    for (i = 0; i < (**gdh).numGroups; i++) {

      gr = GET_GROUP_DATA(gdh, i);
      if (!gr->u.empty && aggHasData(gr,e)) {
	// XXX hack! modify epoch number here for temporal aggregates
	// that may deliver tuples out of order
	if (e->ex.agg.op == kADP_DELTA)
	  qr->epoch = ((TemporalAdpDeltaData *)gr->aggdata)->lastResult.epoch;
			
	err = call QueryResultIntf.addAggResult(qr, gr->groupNo, (char *)gr, (**gdh).groupSize, pq, e->idx);
	
	if (err != err_NoError) {
	  return err;
	}
	gr->u.exprIdx = e->idx;
      }
      
    }

    return err_NoError;

  }

  //Given a tuple built locally, add the result into the locally computed
  //value for the query
  command TinyDBError Operator.processTuple(ParsedQueryPtr qs, TuplePtr t, ExprPtr e) {
    mCurExpr = e;
    mCurQuery = qs;
    mCurTuple = t;
    dbg(DBG_USR1,"in PROCESS_TUPLE, expr = %x\n", (unsigned int)mCurExpr);//fflush(stdout);
    if (e->opState == (OperatorStateHandle)QUERY_DONE_STATE) return err_NoError;
    getGroupData(qs, getGroupNo(t,qs,e) , e, &updateGroupForTuple);
    return err_NoError;
  }


  //epoch ended -- give aggregates a chance to reset themselves,
  //if needed (some aggregates, like windowed and exponentially
  //decaying averages won't reset on every epoch.)
  command result_t Operator.endOfEpoch(ParsedQueryPtr q, ExprPtr e) {
    GroupDataHandle gdh = (GroupDataHandle)e->opState;
    GroupRecord *gr;

    if (e->opType != kSEL && gdh != NULL) {
      short i;
      for (i = 0; i < (**gdh).numGroups; i++) {
	gr = GET_GROUP_DATA(gdh,i);
	initAggregateValue(gr, e, FALSE);
      }
    
    }

    return SUCCESS;
  }

  // finished a query
  event result_t QueryProcessor.queryComplete(ParsedQuery *q) {
    short i;
  
    for (i = 0; i < q->numExprs; i++) {
      Expr e = (call ParsedQueryIntf.getExpr(q, i));
      if (e.opType != kSEL && (e.opState !=  NULL)) {
	call MemAlloc.free((Handle)e.opState);
	dbg(DBG_USR1, "Agg: cleaning up.\n");
	e.opState = (OperatorStateHandle)QUERY_DONE_STATE; //mark it as empty!
      }
    }
    return SUCCESS;
  }


  //callback from getGroupData for PROCESS_TUPLE
  //given the location of the aggregate record
  //for the new tuple, update it
  void updateGroupForTuple(GroupRecord *d) {
    Tuple *t = mCurTuple;
    Expr *e = mCurExpr;
    ParsedQuery *q = mCurQuery;
    char *fieldBytes = call TupleIntf.getFieldPtr(q, t, (char)e->ex.agg.field);
    short size = call TupleIntf.fieldSize(q, (char)e->ex.agg.field);
    short fieldVal = 0;
    short i;

    for (i = 0; i < size; i++) {
      unsigned char b = (*fieldBytes++);
      fieldVal += ((unsigned short)b)<<(i*8);
    }
  
    updateAggregateValue(d,e,fieldVal);

    signal Operator.processedTuple(t, q, mCurExpr,TRUE);
  }


  //allocate is used to create the operator state (which stores all the group
  //records) the first time a value is stored
  event result_t MemAlloc.allocComplete(HandlePtr h, uint8_t success) {
    GroupDataHandle dh = (GroupDataHandle)*h;
    GroupRecord *newGroup;

    if (h != (Handle *)mAlloced) return SUCCESS; //not for us
    mAlloced = NULL;
    dbg(DBG_USR1, "In allocComplete\n");
    if (!success) {
      dbg(DBG_USR1,"Error! Couldn't allocate aggregate data!");
      TDB_SIG_ERR(err_OutOfMemory);
	  return FAIL;
    }
    dbg(DBG_USR1,"in AGG_ALLOC_DONE, expr = %x\n", (unsigned int)mCurExpr);//fflush(stdout);
    (**dh).groupSize = groupSize(mCurExpr);
    (**dh).numGroups = 0;
    newGroup = addGroup(dh, mCurGroup);
    initAggregateValue(newGroup, mCurExpr, TRUE);
    (*mCallback)(newGroup);
    return SUCCESS;
  }


  //reallocate is used when a new group is allocated in the existing operator
  //state
  event result_t MemAlloc.reallocComplete(Handle h, uint8_t success) {
    GroupRecord *newGroup;

  
    if (h != (Handle)mAlloced) return SUCCESS; //not for us
    mAlloced = NULL;
    dbg(DBG_USR1, "In reallocComplete\n");
    if (!success) {
      if (!removeEmptyGroup((GroupDataHandle)h)) { //check for empty groups -- if there are any, reuse them
	//maybe try to evict -- may be not possible
	dbg(DBG_USR1,"Error! Couldn't reallocate aggregate data!");
	TDB_SIG_ERR(err_OutOfMemory);
      }
    }


    newGroup = addGroup((GroupDataHandle)h, mCurGroup);
    initAggregateValue(newGroup, mCurExpr, TRUE);
    (*mCallback)(newGroup);
    return SUCCESS;
  }

  event result_t MemAlloc.compactComplete() {
    return SUCCESS;
  }

  //binary search to locate the group record for the specified
  //group num
  GroupRecord *findGroup(GroupDataHandle dh, short groupNum) {
    short min = 0, max = (**dh).numGroups-1,mid;
    GroupRecord *gr;


    if ((**dh).numGroups == 0) return NULL; // no groups
    while (max >= min) {
      mid = (min + max) >> 1;
      //printf("min = %d, max = %d\n", min, max);
      gr = GET_GROUP_DATA(dh, mid);
      //printf("group no = %d, looking for %d\n", gr->groupNo, groupNum);
      if (gr->groupNo == groupNum) return gr;

      if (gr->groupNo > groupNum)
        max = mid-1;
      else
        min= mid+1;

    }
    return NULL;
  }

  //scan the list of groups and remove one that is empty
  //return true if successful, false if there are no
  //emtpy groups
  bool removeEmptyGroup(GroupDataHandle dh) {
    short i, lastEmpty;
    bool found = FALSE;
    GroupRecord *gr;

    //scan backwards, looking for an empty group
    for (lastEmpty = (**dh).numGroups - 1; lastEmpty >= 0; lastEmpty--) {
      gr = GET_GROUP_DATA(dh,lastEmpty);
      if (gr->u.empty) {
	found = TRUE;
	break;
      }
    }

    if (!found) return FALSE;
    dbg(DBG_USR1,"found empty = %d\n", lastEmpty);
    //now shift everything after that group up one
    for (i = lastEmpty + 1; i < (**dh).numGroups; i++) {
      gr = GET_GROUP_DATA(dh,i);
      SET_GROUP_DATA(dh,i-1,(char *)&gr);
    }

    (**dh).numGroups--;

    return TRUE;
  }

  //add a group to a group data handle that has been realloced to be big enough to hold
  //the group record (we assume the new space is at the end of the data block)
  GroupRecord *addGroup(GroupDataHandle dh, short groupNum) {
    short i;
    bool shift = FALSE, first = FALSE;
    GroupRecord *gr,lastgr,newgr,tempgr,*ret=NULL;
  
    newgr.groupNo = groupNum;

    //do a simple insertion sort
    (**dh).numGroups++;
  
    for (i = 0; i < (**dh).numGroups; i++) {

      gr = GET_GROUP_DATA(dh,i);

      //did we find the place to insert?
      if (!shift && (gr->groupNo > groupNum || i+1 == (**dh).numGroups)) {
	lastgr = newgr; //yup
	shift = TRUE;
	first=TRUE;
      }
    
      if (shift) {  //have we already inserted?
	tempgr = *gr;  //move up the current record
	SET_GROUP_DATA(dh,i,(char *)&lastgr);
	lastgr = tempgr;
	if (first) {
	  first=FALSE;
	  ret = GET_GROUP_DATA(dh,i);
	}
      }
      
    }
    if (ret == NULL) {
      dbg(DBG_USR1,"ERROR: Retval is NULL on addGroup!\n");//fflush(stdout);
    }
    return ret;
  }

  //locate or allocate the group data for the group that t should update,
  //and invoke the callback with that data.
  void getGroupData(ParsedQuery *pq, short groupNo , Expr *e, GroupDataCallback callback) {
    GroupDataHandle dh = (GroupDataHandle)e->opState;

    mCallback = callback;
  
    mCurExpr = e;
    mCurQuery = pq;
    mCurGroup = groupNo;
    dbg(DBG_USR1, "In getGroupData, groupNo = %d, dh = %x\n", groupNo, dh);
    if (dh == NULL) {
      //we've got to allocate this baby
      mAlloced = (Handle) &e->opState; //ick
      if (call MemAlloc.allocate((HandlePtr)&e->opState, groupSize(e) + sizeof(GroupData)) == FAIL)
	{
	  signal MemAlloc.allocComplete((Handle *)&e->opState, FALSE);
	}
    } else {
      GroupRecord *gr;

      //scan through it, looking to see if the needed group is there
      gr = findGroup(dh, groupNo);
      mGroupRecord = gr;
      //decouple so that we don't immediately return (yuck yuck!)
      if (gr != NULL) (*(callback))(gr);
      else {
	//group doesn't exist -- must realloc and continue
	mAlloced = (Handle) e->opState;
	
	if (call MemAlloc.reallocate((Handle)e->opState, groupSize(e) * ((**dh).numGroups + 1) + sizeof(GroupData)) == FAIL) //failure
	  {
	    signal MemAlloc.reallocComplete((Handle)e->opState, FALSE);
	  }
      
      }
    }

  }

    task void fireCallback() {
      (*mCallback)(mGroupRecord);
    }

  short getGroupNo(Tuple *t, ParsedQuery *q, Expr *e) {
    char *fieldBytes;
    short size;
    short fieldVal = 0;
    short i;
    if (e->ex.agg.groupingField == (short)kNO_GROUPING_FIELD) return 0; //we're not using a group!

    
    fieldBytes = call TupleIntf.getFieldPtr(q, t, (char)e->ex.agg.groupingField);
    size = call TupleIntf.fieldSize(q, (char)e->ex.agg.groupingField);


    for (i = 0; i < size; i++) {
      unsigned char b = (*fieldBytes++);
      fieldVal += ((unsigned short)b)<<(i*8);
    }

    return (call ExprEval.evaluateGroupBy(e->ex.agg, fieldVal));
    //(fieldVal) >> e->ex.agg.attenuation); //group number is attenuated by some number of bits
  }
  
   /** @return The group number from this query result */
  command short getGroupNoFromQr(QueryResult *qr) {
    GroupRecord *gr = (GroupRecord *)qr->d.data;
    
    return gr->groupNo;
  }

  //compare two aggregate records, determine if they are equal
  bool aggEqual(GroupRecord *r1, GroupRecord *r2, Expr *e) {
    short size = groupSize(e);
    char *b1 = r1->aggdata;
    char *b2 = r2->aggdata;

    while (size--)
      if (*b1++ != *b2++) return FALSE;

    return TRUE;
  }


  /* ------------------------------------- Aggregation Operator Specific Commands ------------------------------------------- */

/* Return the amount of storage required for an aggregate of the specified group
   Note that this will not generalize to support variable size (e.g. holistic aggregates)
*/
  short groupSize(Expr *e) {
    GroupRecord g;
    short base;
    
    ParamVals paramVals;
    setParamValues(&paramVals,e);
    
    base = sizeof(g) - sizeof(g.aggdata[0]);
    return base + call AggregateUse.stateSize(e->ex.agg.op, NULL, &paramVals);
  }


  /* Given two aggregate records, merge them together into dest. */
  void mergeAggregateValues(GroupRecord *dest, GroupRecord *merge, Expr *e) {
	ParamVals paramVals;
    setParamValues(&paramVals,e);
    
    dest->u.empty = FALSE;
    // the following is ugly
    if (e->ex.agg.op == kADP_DELTA) { //set up current epoch as an arg
		setCurrentEpoch(&paramVals, mCurQuery->currentEpoch);
	}
	
    call AggregateUse.merge(e->ex.agg.op, dest->aggdata, merge->aggdata, NULL, &paramVals);
  }

  /* Given an aggregate value and a group, merge the value into the group */

  void updateAggregateValue(GroupRecord *d, Expr *e, short fieldValue) {
    ParamVals paramVals;
    setParamValues(&paramVals,e);
 
    //dbg(DBG_USR3, "Update called.\n");
    
    fieldValue = call ExprEval.evaluate(e, fieldValue);
    d->u.empty = FALSE;
    
    // the following is ugly
    if (e->ex.agg.op == kADP_DELTA) { //set up current epoch as an arg
		setCurrentEpoch(&paramVals, mCurQuery->currentEpoch);
	}
    call AggregateUse.update(e->ex.agg.op, d->aggdata, (char *)&fieldValue, NULL, &paramVals);
  }


  /* Initialize the value of the specified aggregate value. */

  void initAggregateValue(GroupRecord *d, Expr *e, bool isFirstTime) {
    ParamVals paramVals;
    setParamValues(&paramVals,e);
    
    //dbg(DBG_USR3, "Init called.\n");
    d->u.empty = TRUE;
    
    call AggregateUse.init(e->ex.agg.op, d->aggdata, NULL, &paramVals, isFirstTime);
  }
  

  /* Return true if this aggregate has data ready right now
     -- some aggregates, such as windowed averages, only
     produce data at the end of several epochs.
  */
  bool aggHasData(GroupRecord *gr, Expr *e) {
  	ParamVals paramVals;
  	setParamValues(&paramVals, e);
  	
  	return call AggregateUse.hasData(e->ex.agg.op, gr->aggdata, NULL, &paramVals);
  }

  command TinyDBError finalizeAggExpr(QueryResult *qr, ParsedQueryPtr q, Expr *e, char *result_buf) {
    GroupRecord *gr = (GroupRecord *)qr->d.data;
    
    ParamVals paramVals;
    setParamValues(&paramVals,e);
    //dbg(DBG_USR3, "Finalize Aggr Expr called.\n");
    return call AggregateUse.finalize(e->ex.agg.op, gr->aggdata, result_buf, NULL, &paramVals);
  }
  
  /*****************************************************************************
   * Functions for optimizing aggregates result routing
   ****************************************************************************/
  
  /*
   * Returns TRUE if local result can affect final result given snooped result
   */
  bool localDataAffectsResult(GroupRecord *local, GroupRecord *snooped, Expr *e) {
  	ParamVals paramVals;
  	AggregateProperties properties;
  	int16_t resultBefore, resultAfter;
  	
    setParamValues(&paramVals,e);
    
    properties = call AggregateUse.getProperties(e->ex.agg.op);
    
    if (isMonotonic(properties) && isExemplary(properties)) {// MIN, MAX-like aggregates
    	//finalize snooped
    	// using ints instead of buffers is a dirty hack. OK FOR NOW?
    	call AggregateUse.finalize(e->ex.agg.op, snooped->aggdata, (char *) &resultBefore, NULL, &paramVals);
    	//aplly merge(snooped, local). Notice snooped is destination
    	call AggregateUse.merge(e->ex.agg.op, snooped->aggdata, local->aggdata, NULL, &paramVals);
    	//finalize snooped again
    	call AggregateUse.finalize(e->ex.agg.op, snooped->aggdata, (char *) &resultAfter, NULL, &paramVals);
    	//if result changed, local data affects it!
    	return (resultBefore != resultAfter);
    }
    
	return TRUE;
  }
  
  
}

