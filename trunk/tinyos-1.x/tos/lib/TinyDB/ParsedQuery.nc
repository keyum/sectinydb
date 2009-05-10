// $Id: ParsedQuery.nc,v 1.8 2003/10/07 21:46:20 idgay Exp $

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

includes Aggregates;

module ParsedQuery {
  provides {
    interface ParsedQueryIntf;
  }
  uses {
    interface Operator as AggOperator;
    interface TupleIntf;
    interface AttrUse;
    interface QueryResultIntf;
    interface Leds;
    interface Table;
    interface DBBuffer;
#ifdef kUART_DEBUGGER
    interface Debugger as UartDebugger;
#endif
    command TinyDBError finalizeAggExpr(QueryResult *qr, ParsedQueryPtr q, Expr *e, char *result_buf);
    command short getGroupNoFromQr(QueryResult *qr);
  }
}

implementation {


  command bool ParsedQueryIntf.queryFieldIsNull(uint8_t field) {
    //high bit of query field indicates field is null
    return (field & NULL_QUERY_FIELD) > 0;
  }
  
  command bool ParsedQueryIntf.queryFieldIsTyped(uint8_t field) {
    return (field & TYPED_FIELD)  == TYPED_FIELD;
  }

  command Expr ParsedQueryIntf.getExpr(ParsedQueryPtr q, uint8_t n) {
    return *(Expr *)(&((char *)q)[sizeof(ParsedQuery) + (q->numFields - 1) * sizeof(char) + n * sizeof(Expr)]);
  }

  command ExprPtr ParsedQueryIntf.getExprPtr(ParsedQueryPtr q, uint8_t n) {
    return (Expr *)(&((char *)q)[sizeof(ParsedQuery) + (q->numFields - 1) * sizeof(char) + n * sizeof(Expr)]);
  }

  command uint8_t ParsedQueryIntf.getFieldId(ParsedQueryPtr q, uint8_t n) {
    return (q->queryToSchemaFieldMap[n]); //note:  may be NULL_QUERY_FIELD
  }

  command result_t ParsedQueryIntf.setExpr(ParsedQueryPtr q, uint8_t n, Expr e) {
    (*(Expr *)(&((char *)q)[sizeof(ParsedQuery) + (q->numFields - 1) * sizeof(char) + n * sizeof(Expr)])) = e;
    return SUCCESS;
  }

  command TuplePtr ParsedQueryIntf.getTuplePtr(ParsedQueryPtr q) {
    return (Tuple *)(&((char *)q)[sizeof(ParsedQuery) + (q->numFields - 1) * sizeof(char) + (q->numExprs) * sizeof(Expr)]);
  }

  command short ParsedQueryIntf.baseSize(QueryPtr q) {
    return sizeof(ParsedQuery) +  (sizeof(char) * ((q)->numFields - 1))  +  (sizeof(Expr) * ((q)->numExprs));
  }


  command short ParsedQueryIntf.pqSize(ParsedQueryPtr pq) {
    return sizeof(ParsedQuery) +  (sizeof(char) * ((pq)->numFields - 1))  +  (sizeof(Expr) * ((pq)->numExprs));
  }

  command uint8_t ParsedQueryIntf.numResultFields(ParsedQueryPtr q, bool *agg) {
    short i;
    Expr *e;
    short numAggs = 0;

    for (i = 0; i < q->numExprs; i++) {
      e = call ParsedQueryIntf.getExprPtr(q, i);
      if (e->opType != kSEL) {
	numAggs++;
      }
    }

    
    if (numAggs > 0) {
      *agg = TRUE;
      return numAggs;
    } else {
      *agg = FALSE;
      return q->numFields;
    }
  }

  /** Copy data from the field resultid (as returned by getResultId) of qr into result_buf
   */
  command TinyDBError ParsedQueryIntf.getResultField(ParsedQueryPtr q, QueryResultPtr qr, uint8_t resultid, char *result_buf) {
    QueryResult localqr;
    ResultTuple rt;
    short numRecords = call QueryResultIntf.numRecords(qr,q);
    bool isAgg = (qr->qrType != kNOT_AGG);
    uint8_t fieldId = resultid & 0x7F;
    bool isGroupNo = (resultid == GROUP_FIELD); //are we just returning the group number?
    TinyDBError err;

    if (resultid == NULL_QUERY_FIELD || resultid == TYPED_FIELD) {

      return err_InvalidIndex;
    }

    if (!isAgg) {
      Tuple *t;
      char *data;

      err = call QueryResultIntf.toTuplePtr(qr, q, &t);
      if (err != err_NoError) return err;
      
      data = call TupleIntf.getFieldPtr(q, t, fieldId);
      if (data == NULL) return err_InvalidIndex;

      memcpy(result_buf, data, call TupleIntf.fieldSize(q,fieldId));
     
      return err_NoError;
    } else {
      Expr *e = isGroupNo?NULL:call ParsedQueryIntf.getExprPtr(q, fieldId);
      short i;

      for (i = 0; i < numRecords; i++) {
	//look for a ResultTuple for the appropriate expression
	rt = call QueryResultIntf.getResultTuple(qr, i, q);
	err = call QueryResultIntf.fromResultTuple(rt, &localqr, q);
	if (err != err_NoError) {
	  return err;
	}
	if (isGroupNo) {
	  *(short *)result_buf = call getGroupNoFromQr(&localqr);
	  return err_NoError;
	} else {
	  if (call AggOperator.resultIsForExpr(&localqr, e)) {
	    err = call finalizeAggExpr(&localqr, q , e, result_buf);
	    if (err != err_NoError) {
	      return err;
	    }
	    else return err_NoError;
	  }
	}
      }
    }


    return err_InvalidIndex;
  }

/*    char mDbgMsg[20]; */

  /** Set id to the be the index into query results from q corresponding to field f
     Return err_InvalidIndex if the query does not contain a corresponding field
  */
  command TinyDBError ParsedQueryIntf.getResultId(ParsedQueryPtr q, Field *f, uint8_t *id) {
    AttrDescPtr attr = call AttrUse.getAttr(f->name);
    uint8_t i;
    uint8_t fid = 0xFF;
/*        char map[5];  */

/*        mDbgMsg[0] = 0;  */
    

    if (attr != NULL) {
/*          itoa(attr->idx, map, 10);  */
/*          strcat(mDbgMsg, map);  */
/*          strcat(mDbgMsg, ","); */

      for (i = 0; i < q->numFields; i++) {
/*    	itoa(q->queryToSchemaFieldMap[i], map, 10);	  */
/*    	strcat(mDbgMsg, map);  */
/*    	strcat(mDbgMsg, ",");  */

	if (q->queryToSchemaFieldMap[i] == attr->idx) {
	  fid = i;
	}

      }
/*          call UartDebugger.writeLine(mDbgMsg, strlen(mDbgMsg));  */
    }
    
    
    if (fid == 0xFF) {
      //didn't find the field here -- scan now and
      //see if the field is in the named list (e.g. aliases or named table fields)
      if (q->tableInfo != NULL) {
	if (call Table.getNamedField(q, f->name, &fid) == FAIL) {
	  return err_InvalidIndex;
	}
      }
    }

    if (fid == 0xFF) return err_InvalidIndex;

    //see if we're grouping by this field
    //if so, return the magic group by code
    //so that our caller knows to look in the
    //group by field of query resutls
    for (i = 0; i < q->numExprs; i++) {
	Expr *e = call ParsedQueryIntf.getExprPtr(q, i);
	if (e->opType != kSEL && e->ex.agg.groupingField == fid) {
	  *id = GROUP_FIELD;
	  return err_NoError;
	}
    }

    if (f->op == kNOOP) {
      *id = fid;
      return err_NoError;
    } else {
      for (i = 0; i < q->numExprs; i++) {
	Expr *e = call ParsedQueryIntf.getExprPtr(q, i);
	if (e->opType != kSEL && e->ex.agg.field == fid && e->ex.agg.op == f->op) {
	  //found it!
	  *id = e->idx;
	  return err_NoError;
	}
      }
    }
    
    //didn't find it
    return err_InvalidIndex;
    
  }

  /** Return the type of the specified field index from
      pq in type.  Return FAIL if the index is invalid,
      or the field is NULL.
      @param pq The query to get the field type from
      @param fieldIdx The index of the field whose type is desired
      @param type (on return) The type of the requested field
      @return FAIL if the index is valid or the field is NULL
  */
  command result_t ParsedQueryIntf.getFieldType(ParsedQuery *pq, uint8_t fieldIdx,
						uint8_t *type) {
    AttrDescPtr attr;

    if (fieldIdx >= pq->numFields ||
	call ParsedQueryIntf.queryFieldIsNull(pq->queryToSchemaFieldMap[fieldIdx])) return FAIL;

    //does this field have a separate type associated with it?
    if (call ParsedQueryIntf.queryFieldIsTyped(pq->queryToSchemaFieldMap[fieldIdx])) {
      result_t success;

      success = call Table.getType(pq, fieldIdx, type);

      return success;
    }

    //does this field represent an attribute, or a selection from another query?
    if (pq->fromBuffer != kNO_QUERY) { // from another query
      uint8_t bufId;
      uint8_t fid = pq->queryToSchemaFieldMap[fieldIdx];
      
      //fetch the other query
      TinyDBError err = call DBBuffer.getBufferId(pq->fromBuffer,
						  pq->fromCatalogBuffer,
						  &bufId);
      ParsedQuery **fromSchema;
      if (err != err_NoError) return FAIL;
      fromSchema = call DBBuffer.getSchema(bufId);
      if (call ParsedQueryIntf.queryFieldIsNull((**fromSchema).queryToSchemaFieldMap[fid])) return FAIL;

      //and get the attribute associated with the appropriate field in that query
      attr = call AttrUse.getAttrById((**fromSchema).queryToSchemaFieldMap[fid]);

    } else { //from an attribute
      attr = call AttrUse.getAttrById(pq->queryToSchemaFieldMap[fieldIdx]);
    }
    if (attr != NULL) {
      *type = attr->type;
      return SUCCESS;
    } else
      return FAIL;
    
  }

  /** Verify that the schema of the destination query matches the
      schema of the select query.  The dest query must create a buffer and
      have a table of named fields set up.  The number, order, and type of
      these fields must match the fields in the select query.
      @param dest A ParsedQuery with a Table of named, typed fields
      @param select A ParsedQuery that will insert into dest
  */
  command bool ParsedQueryIntf.typeCheck(ParsedQuery *dest, ParsedQuery *select) {
    int i;
    uint8_t selType, destType;

    if ((dest->bufferType != kRAM && dest->bufferType != kEEPROM) || dest->buf.ram.create != 1)
      {

	return FALSE;
      }
    if (dest->numFields != select->numFields) {

      return FALSE;
    }

    for (i=0;i<dest->numFields;i++) {
      
      if (call ParsedQueryIntf.getFieldType(select, i, &selType) == FAIL) {
	return FALSE;
      }
      if (call ParsedQueryIntf.getFieldType(dest, i, &destType) == FAIL) {
	return FALSE;
      }
      if (selType != destType)  {
	//call UartDebugger.writeLine("neq", 3);
	return FALSE;
      }
    }
    return TRUE;
  }

#ifdef kUART_DEBUGGER
async  event result_t UartDebugger.writeDone(char *buf, result_t success) {
    return SUCCESS;
  }
#endif

  /* ---------------------------------------- EVENT HANDLERS ---------------------------------------- */
  event result_t AttrUse.getAttrDone(char *name, char *resultBuf, SchemaErrorNo errorNo) {
    return SUCCESS;
  }

  event result_t AttrUse.startAttrDone(uint8_t id) {
    return SUCCESS;
  }

  event TinyDBError AggOperator.processedResult(QueryResultPtr qr, ParsedQueryPtr q, ExprPtr e) {
    return err_NoError;
  }

  event TinyDBError AggOperator.processedTuple(TuplePtr t, ParsedQueryPtr q, ExprPtr e, bool passed) {
    return err_NoError;
  }

  event result_t Table.addNamedFieldDone(result_t success) {
    return SUCCESS;
  }

  event result_t DBBuffer.resultReady(uint8_t bufferId) {
    return SUCCESS;
  }

  event result_t DBBuffer.getNext(uint8_t bufferId) {
    return SUCCESS;
  }

  event result_t DBBuffer.allocComplete(uint8_t bufferId, TinyDBError result) {
    return SUCCESS;
  }

  /* Signalled when a get is complete */
  event result_t DBBuffer.getComplete(uint8_t bufferId, QueryResult *buf, TinyDBError result) {
    return SUCCESS;
  }
  
  /* Signalled when a put is complete */
  event result_t DBBuffer.putComplete(uint8_t bufferId, QueryResult *buf, TinyDBError err) {
    return SUCCESS;
  }

#ifdef kMATCHBOX
  event result_t DBBuffer.loadBufferDone(char *name, uint8_t id, TinyDBError err) {
    return SUCCESS;
  }

  event result_t DBBuffer.writeBufferDone(uint8_t bufId, TinyDBError err) {
    return SUCCESS;
  }

  event result_t DBBuffer.deleteBufferDone(uint8_t bufId, TinyDBError err) {
    return SUCCESS;
  }

  event result_t DBBuffer.cleanupDone(result_t success) {
    return SUCCESS;
  }
#endif

  event result_t DBBuffer.openComplete(uint8_t bufId, TinyDBError err) {
    return SUCCESS;
  }




}
