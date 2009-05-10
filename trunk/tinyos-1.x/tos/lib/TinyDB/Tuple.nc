// $Id: Tuple.nc,v 1.6 2003/10/07 21:46:21 idgay Exp $

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


includes SchemaType;

/* Routines to manage a tuple */
module Tuple {
  provides {
    interface TupleIntf;
  }
  uses {
    interface AttrUse;
    interface ParsedQueryIntf;
    interface QueryProcessor;
    interface CatalogTable;
    interface Table;
    interface DBBuffer;
#ifdef kUART_DEBUGGER
    interface Debugger as UartDebugger;
#endif
  }
}

implementation {
  uint16_t typeToSize(TOSType type);

  //return the size of a tuple for a given query
  command uint16_t TupleIntf.tupleSize(ParsedQueryPtr q) {
    short i;
    short size = sizeof(Tuple);

    for (i = 0 ; i < q->numFields; i++) {
      size += call TupleIntf.fieldSize(q, (uint8_t)i);
      
    }
    return size;
    
  }
  
  //return the size of a field for a given query
  command uint16_t TupleIntf.fieldSize(ParsedQueryPtr q, uint8_t fieldNo) {
    if (q->fromCatalogBuffer) {
      uint8_t from_fieldNo = q->queryToSchemaFieldMap[(short)fieldNo];
      return call CatalogTable.catalogFieldSize(q->fromBuffer, from_fieldNo);
    } else if (q->fromBuffer != kNO_QUERY) {
      int8_t bufferId;
      ParsedQuery *fromq;
      uint8_t from_fieldNo = q->queryToSchemaFieldMap[(short)fieldNo];

      call DBBuffer.getBufferId(q->fromBuffer, FALSE, &bufferId);
      fromq = *(call DBBuffer.getSchema(bufferId));

      if (fromq == NULL) {
#ifdef kUART_DEBUGGER
	  call UartDebugger.writeLine("NO BUF", 6);
#endif
	  return 0;
      }
      
      if (!call ParsedQueryIntf.queryFieldIsNull(fromq->queryToSchemaFieldMap[(short)from_fieldNo])) {
	if (fromq->queryToSchemaFieldMap[(short)from_fieldNo] == GROUP_FIELD)
	  return typeToSize(UINT16); //group is 16bits
	else {
	  AttrDescPtr attr = NULL;
	  if (call ParsedQueryIntf.queryFieldIsTyped(fromq->queryToSchemaFieldMap[(short)from_fieldNo])) {
	    if (fromq->tableInfo != NULL) {
	      char *name;
	      call Table.getFieldName(fromq, from_fieldNo, &name);
	      attr = call AttrUse.getAttr(name);
	    }
	  } else
	    attr = call AttrUse.getAttrById(fromq->queryToSchemaFieldMap[(short)from_fieldNo]);
	  if (attr != NULL) 
	    return typeToSize(attr->type);
	  else
	    return 0;
	}
	  
      } else
	return 0;
    } else {
      if (!call ParsedQueryIntf.queryFieldIsNull(q->queryToSchemaFieldMap[(short)fieldNo])) {
	if (call ParsedQueryIntf.queryFieldIsTyped(q->queryToSchemaFieldMap[(short)fieldNo])) {
	  if (q->tableInfo == NULL) 
	    return 0;
	  else {
	    uint8_t type;
	    if ((call Table.getType(q,(short)fieldNo, &type)) == SUCCESS)
	      return typeToSize(type);
	  }
	} else {
	  AttrDescPtr attr = call AttrUse.getAttrById(q->queryToSchemaFieldMap[(short)fieldNo]);
	  if (attr != NULL)
	    return typeToSize(attr->type);
	  else
	    return 0;
	}
      } else
	return 0;
    }
    return 0;
  }

  /* Set the value of a specified field to data */
  command result_t TupleIntf.setField(ParsedQueryPtr q, TuplePtr t, uint8_t fieldIdx, CharPtr data) {
    char *dest = call TupleIntf.getFieldPtr(q, t, fieldIdx);
    if (dest == NULL) return FAIL;
    if (dest != data)
      memcpy(dest, data, call TupleIntf.fieldSize(q, fieldIdx));
    t->notNull |= (1 << fieldIdx);
    return SUCCESS;
  }

  /* Set the value of the specified field to data, using the
     provided length and type arrays instead of a query for
     offset information.
  */
  command result_t TupleIntf.setFieldNoQuery(TuplePtr t, 
					    uint8_t fieldIdx, 
					    uint8_t numFields, 
					    uint8_t sizes[], 
					    uint8_t types[], 
					    CharPtr data) {
    char *dest = call TupleIntf.getFieldPtrNoQuery(t, fieldIdx, numFields, sizes, types);
    if (dest != data) {
      memcpy(dest,data, sizes[fieldIdx]);
    }
    t->notNull |= (1 << fieldIdx);
    return SUCCESS;
  }

  /* Get the value of the specified field in the specified tuple
     of the specified query
     fieldIdx begins at 0
  */

  command CharPtr TupleIntf.getFieldPtr(ParsedQueryPtr q, TuplePtr t, uint8_t fieldIdx){
    short i;
    short offset = 0;

    //    if ((t->notNull & (1 << fieldIdx)) == 0 ) return NULL;    
    if (call TupleIntf.fieldSize(q,fieldIdx) == 0) return NULL;
    for (i = 0; i < fieldIdx; i++) {
      offset += call TupleIntf.fieldSize(q, i);
    }
    return (char *)(&t->fields[offset]);    
  }


  /* Return a pointer to the specified field in the tuple,
     using the provided size and type arrays instead
     of a query to computer the offset.
  */
  command CharPtr TupleIntf.getFieldPtrNoQuery(TuplePtr t, 
					       uint8_t fieldIdx, 
					       uint8_t numFields, 
					       uint8_t sizes[], 
					       uint8_t types[]) {
    short i;
    short offset = 0;
    for (i = 0; i < fieldIdx; i++) {
      offset += typeToSize(types[i]);
    }
    return (char *)(&t->fields[offset]);
  }

  
  //reset the specified tuple to be empty
  command result_t TupleIntf.tupleInit(ParsedQueryPtr q, TuplePtr t){
    t->notNull = 0; //all fields null
    t->qid = q->qid;
    t->numFields = q->numFields;
    
    return SUCCESS;
    
  }

  //return true iff the query is complete (e.g. all fields that are not supposed to be null are non-null)
  command bool TupleIntf.isTupleComplete(ParsedQueryPtr q, TuplePtr t){
    short i;
    
    for (i = 0; i < q->numFields; i++) {
      if (!call ParsedQueryIntf.queryFieldIsNull(q->queryToSchemaFieldMap[i])) { //if field is not supposed to be null
	if ((t->notNull & (1 << i)) == 0) return FALSE; //but it is, return false
      }
    }
    return TRUE;  //all fields that are not supposed to be null are non-null
  }

  //scan the tuple, looking for null fields that shouldn't be null
  //(e.g. fields that need to be filled in)
  //return the attr desc of the first one
  command AttrDescPtr TupleIntf.getNextQueryField(ParsedQueryPtr q, TuplePtr t){
    uint8_t i;
    TinyDBError err;

    err = call TupleIntf.getNextEmptyFieldIdx(q,t,&i);
    if (err == err_NoError) {
	return call AttrUse.getAttrById(q->queryToSchemaFieldMap[i]);
    } else
	return NULL;
  }

  //scan the tuple, looking for null fields that shouldn't be null
  //(e.g. fields that need to be filled in)
  //return the index of the first one
  command TinyDBError TupleIntf.getNextEmptyFieldIdx(ParsedQueryPtr q, TuplePtr t, uint8_t *fieldIdx) {
      short i;

      for (i = 0; i < q->numFields; i++) {
	  if (!call ParsedQueryIntf.queryFieldIsNull(q->queryToSchemaFieldMap[i]) && //shouldn't be null
	      (t->notNull & (1 << i)) == 0 ) { //but is
	      *fieldIdx = i;
	      return err_NoError;
	  }
      }
      return err_NoMoreResults;
  }


  uint16_t typeToSize(TOSType type) {
    return sizeOf(type);
  }

  event result_t AttrUse.getAttrDone(char *name, char *resultBuf, SchemaErrorNo errorNo) {
    return SUCCESS;
  }

  event result_t AttrUse.startAttrDone(uint8_t id) {
    return SUCCESS;
  }

  event result_t QueryProcessor.queryComplete(ParsedQueryPtr q) {
    return SUCCESS;
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




#ifdef kUART_DEBUGGER
  async event result_t  UartDebugger.writeDone(char *c, result_t success) {
    return SUCCESS;
  }
#endif


}
