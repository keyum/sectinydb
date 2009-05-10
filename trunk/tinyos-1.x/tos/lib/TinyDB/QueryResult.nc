// $Id: QueryResult.nc,v 1.7 2003/10/07 21:46:20 idgay Exp $

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

/** Query result represents the outcome of a query
   This is not just a tuple since aggregation queries 
   produce mutliple result tuples.
   
   This module defines routines to marshall / unmarshall query results
   from tuples and into and out of byte arrays.

   @author Sam Madden   
 * @author Sam Madden
 * @author Design by Sam Madden
 * @author Wei Hong
 * @author and Joe Hellerstein
 */


module QueryResult {
  provides {
    interface QueryResultIntf;
  }
  
  uses {
    interface TupleIntf;
    interface MemAlloc;
    interface ParsedQueryIntf;
    interface Leds;
  }
}

implementation {
    enum {
      BUF_SIZE = 30
    };
    

    //init a query result
    command TinyDBError QueryResultIntf.initQueryResult(QueryResultPtr qr) {

      qr->qrType = kUNDEFINED;
      qr->result_idx = 0;

      return err_NoError;
    }
    
    /** Fill out a query result with a single tuple's values 
       Don't just copy a reference to the tuple, since they user may want to
       generate query results from a specified tuple, and then reuse the tuple
       for other purposes
    */
    command TinyDBError QueryResultIntf.fromTuple(QueryResultPtr qr, ParsedQueryPtr pq, TuplePtr t) {
      short size = call TupleIntf.tupleSize(pq);
      char *p,*q;
      
      qr->qrType = kNOT_AGG;
      qr->qid = pq->qid;
      qr->result_idx = 0;
      p = (char *)t;
      q = (char *)&qr->d.t;
      while (size--)
	*q++ = *p++;
      return err_NoError;

    }

    /** Return a tuple from a query result.  Note that the resulting tuple may be a pointer
       into the query result data structure 
    */
    command TinyDBError QueryResultIntf.toTuplePtr(QueryResultPtr qr, ParsedQueryPtr q, TupleHandle t) {
      *t = &qr->d.t;
      return err_NoError;

    }

    /** Write the query result into the specified byte array.  The number of bytes written
       is guarantted not to exceed QUERY_RESULT_SIZE(qr,q)

    */
    command TinyDBError QueryResultIntf.toBytes(QueryResultPtr qr, ParsedQueryPtr pq, CharPtr bytes) {
      short size = sizeof(QueryResult) - sizeof(qr->d); //TOS_CALL_COMMAND(QR_TUPLE_SIZE)(pq) + sizeof(*qr) - sizeof(qr->d);
      char *p,*q;
      
      //make damn sure this is a proper query result
      if ((qr->qrType != kIS_AGG &&
	   qr->qrType != kNOT_AGG &&
	   qr->qrType != kAGG_SINGLE_FIELD))
	return err_UnknownError;

      if (qr->qrType != kIS_AGG) {
	size += call TupleIntf.tupleSize(pq); //sizeof(qr->d);
      }

      q = (char *)bytes;
      p = (char *)qr;
      while (size--)
	*q++=*p++;

      if (qr->qrType == kIS_AGG) {
	short i;
	for (i = 0; i < qr->result_idx; i++) {
	  //now write the individual results out after the QueryResult
	  //group
	  *(int16_t *)q = qr->d.buf[i].group;
	  q += sizeof(int16_t);

	  //length
	  //*(uint8_t *)q = qr->d.buf[i].len;
	  //q += sizeof(uint8_t);

	  //followed by len bytes of data
	  size = BUF_SIZE;//qr->d.buf[i].len;
	  p = qr->d.buf[i].data;
	  while (size--)
	    *q++ = *p++;
	}
      }
      return err_NoError;
    }

    /** Convert the specified set of bytes into a query result 
       If this result represents an aggregate of multiple fields, 
       This query result must already have been allocated via initQueryResult so that
       the appropriate storage is available (returns err_OutOfMemory if this is not the case
       or the byte array is too long to fit in the available storage.)
       First byte is the offset into bytes to copy from.
     */
    command TinyDBError QueryResultIntf.fromBytes(QueryResultPtr bytes, QueryResultPtr qr, ParsedQueryPtr pq) {
      short size = sizeof(QueryResult) - sizeof(qr->d); //TOS_CALL_COMMAND(QR_TUPLE_SIZE)(pq) + (sizeof(*qr) - sizeof(qr->d));
      char *p,*q;

      q = (char *)qr;
      p = (char *)bytes;
      while (size--)
	*q++ = *p++;
      
      if (qr->qrType == kIS_AGG) { //query result is pointers into the byte array
	short i;
	
	for (i = 0; i < qr->result_idx; i++) {
	  qr->d.buf[i].group = *(uint16_t *)p;
	  p += sizeof(uint16_t);
	  //qr->d.buf[i].len = *(uint8_t *)p;
	  //p += sizeof(uint8_t);

	  qr->d.buf[i].data = p;
	  p += BUF_SIZE; //qr->d.buf[i].len;
	}

      } else { //for non aggregate records, the rest of the data just follows immediately
		size = (qr->qrType == kAGG_SINGLE_FIELD)?sizeof(qr->d):call TupleIntf.tupleSize(pq); //sizeof(qr->d);
		while (size--)
		  *q++ = *p++;
      }
      
      return err_NoError;

    }

    //Given a ResultTuple, convert it to a QueryResult
    command TinyDBError QueryResultIntf.fromResultTuple(ResultTuple r, QueryResultPtr qr, ParsedQueryPtr pq) {
      qr->qid = r.qid;
      qr->qrType = r.isAgg?kAGG_SINGLE_FIELD:kNOT_AGG;
      qr->epoch = r.epoch;

      if (r.isAgg) {
	qr->result_idx = r.u.agg.id;
	memcpy(qr->d.data, r.data, BUF_SIZE /*r.u.agg.len*/);
      } else {
	qr->result_idx = 0;
	memcpy((char *)&qr->d.t, r.data, call TupleIntf.tupleSize(pq));
      }

      return err_NoError;

    }


    /** Return the query id corresponding to a stream of bytes representing a query result
       (So that callers can determine the value of q to pass into to QUERY_RESULT_FROM_BYTES)
    */
    command uint8_t QueryResultIntf.queryIdFromMsg(QueryResultPtr qr) {
      return qr->qid;
    }

    /** Return the size required to store the specified query result in a byte
       stream, in bytes 
    */
    command uint16_t QueryResultIntf.resultSize(QueryResultPtr qr, ParsedQueryPtr q) {
      uint16_t size;
      
      switch (qr->qrType) {
      case kIS_AGG:
	size = sizeof(QueryResult) - sizeof(qr->d);
	size += (sizeof(uint16_t) + BUF_SIZE) * qr->result_idx;
	break;
      case kAGG_SINGLE_FIELD:
	size = sizeof(QueryResult);
	break;
      case kNOT_AGG:
	size = sizeof(QueryResult) - sizeof(qr->d) + (call TupleIntf.tupleSize(q));
	break;
      default:
	size = 0;
      }

      return size;
      
    }

    
    /** @Return the number of records in this result */
    command short QueryResultIntf.numRecords(QueryResultPtr qr, ParsedQueryPtr q) {
      if (qr->qrType == kIS_AGG) {
	return qr->result_idx;
      }	else if (qr->qrType == kAGG_SINGLE_FIELD) {
	return 1;
      } else if (qr->qrType == kNOT_AGG) {
	//return call ParsedQueryIntf.numResultFields(q, &agg);
	return 1; //tuples are just a single result
      } else
	return 0; //uninitialized -- no results
    }


    /** get information about a specified sub tuple */
    command ResultTuple QueryResultIntf.getResultTuple(QueryResultPtr qr, short i, ParsedQueryPtr q) {
      ResultTuple rf;

      rf.error = err_NoError;


      if (i >= call QueryResultIntf.numRecords(qr,q)) {
	rf.error = err_IndexOutOfBounds;
      }

      rf.qid = qr->qid;
      rf.isAgg = (qr->qrType == kIS_AGG);
      rf.epoch = qr->epoch;
      
      if (qr->qrType == kIS_AGG) {
	rf.u.agg.group = qr->d.buf[i].group;
	rf.u.agg.id = i;
	rf.u.agg.len = BUF_SIZE;
	rf.data = qr->d.buf[i].data;
      } else if (qr->qrType == kAGG_SINGLE_FIELD) {
	rf.u.agg.id = 0;
	rf.u.agg.group = kNO_GROUPING_FIELD;
	rf.u.agg.len = BUF_SIZE;
	rf.data = (char *)(qr->d.data);
      } else {
	rf.u.tupleField = i;
	rf.data = (char *)&qr->d.t;
      }

      return rf;


    }

    /** Add an agggreate result for the specified query for the specified expression<ul>
    <li> If this query result has already been initialized from a tuple, returns err_AlreadyTupleResult
    <li> If this query result contains results for a different query id, return err_InvalidQueryId
    <li> If a alloc is pending, return err_AllocPending </ul>
    @param qr The query result to add the aggregate data to
    @param groupNo The group number for the aggregate data
    @param bytes The aggregate data
    @param size The size (in bytes) of the aggregate data
    @param q The query this result/data correspond to
    @param exprIdx The expression in q that this is aggregate data for
    @return err_OutOfMemory if there is insufficient space in the result
    @return err_AlreadyTupleResult if this query result already has base tuple data in it
    @return err_InvalidQueryId qr is not a result for query q
    @return err_NoError if there was no error
    */

    command TinyDBError QueryResultIntf.addAggResult(QueryResultPtr qr, 
						     int16_t groupNo, 
						     char *bytes, 
						     int16_t size, 
						     ParsedQueryPtr q, 
						     short exprIdx) {

      if (size > BUF_SIZE) return err_OutOfMemory;
      if (qr->qrType == kNOT_AGG) return err_AlreadyTupleResult;

      if (qr->qrType == kIS_AGG && qr->qid != q->qid)
	return err_InvalidQueryId;
      else {
	qr->qid = q->qid;
	qr->qrType = kIS_AGG;
      }
      qr->d.buf[(short)qr->result_idx].data = bytes;
      //qr->d.buf[qr->result_idx].len = (uint8_t)(size & 0x00FF);
      qr->d.buf[(short)qr->result_idx].group = groupNo;
      //qr->d.buf[qr->result_idx].exprId = exprIdx;
      qr->result_idx++;
      
      return err_NoError;
    }

    event result_t MemAlloc.allocComplete(HandlePtr handle, result_t success) {
      return SUCCESS;
    }

    event result_t MemAlloc.reallocComplete(Handle handle, result_t success) {
      return SUCCESS;
    }

    event result_t MemAlloc.compactComplete() {
      return SUCCESS;
    }

    //note that we do not provide methods to automatically convert query results to / from network messages



}
