// $Id: QueryResultIntf.nc,v 1.4 2003/10/07 21:46:21 idgay Exp $

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


includes TinyDB;

/** QueryResults are collections tuples or partially aggregated results, either produced locally or
   received over the network.
<p>
   This interface defines routines to marshall / unmarshall them from tuples and
   byte arrays.
<p>
    Note that QueryResults (or ResultTuples) should not be
confused with Tuples (see TupleIntf) which are simple, fixed width
packed arrays of attribute data collected from local fields. Tuples
are used internally to collect data about sensors -- QueryResults are
sent to neighboring motes and stored in result buffers for external
processing. 
<p>
ResultTuples can be used to get information about specified subtuples of a result.
ResultTuple is defined in TinyDB.h.
They are either aggregates (in which case the individual ResultTuples should be
converted to QueryResults via fromResultTuple and passed to AggOperator for
processing), or 
<p>
Note that you must be careful with QueryResults, since they are sometimes initalized with
pointers into the data structures that they are created from, such that overwriting
their data can cause dangerous things to happen and the underlying pointers can become
invalid when current tuples / buffers are reused.  Situations in which references
may be returned are noted carefully below (usually this is done for large results
for which extra copies would incur a significant memory overhead).

@author Sam Madden
*/
interface QueryResultIntf
{
    /** Reset / initialize the specified query result so that it contains no data
	(does NOT deallocate memory associated with prior data stored in the result
	@param qr The query result to initialize.
    */
    command TinyDBError initQueryResult(QueryResultPtr qr);

    /** Create a QueryResult from a TuplePtr.  Copies data from t (not just references!)
	@param qr The (initialized) QueryResult to fill in
	@param q The query that t belongs to
	@param t The tuple to write into the QueryResult

    */
    command TinyDBError fromTuple(QueryResultPtr qr, ParsedQueryPtr q, TuplePtr t);
    
    /** Create a Tuple from q QueryResult.  The returned tuple is a reference into the
	query result.  Should only be called if the type qr->qrType == kNOT_AGG.
      
	@param qr The QueryResult to build the tuple from
	@param q The query corresponding to the query result / tuple
	@param t (on return) The tuple containing the data from the query result
    */
    command TinyDBError toTuplePtr(QueryResultPtr qr, ParsedQueryPtr q, TupleHandle t);
    

    /** @return the size (in bytes) requiired to marshall the specified query result  for the spceified query */
    command uint16_t resultSize(QueryResultPtr qr, ParsedQueryPtr q);

    /** Marshall the specified query result into a byte array.  The byte array must be at least
	resultSize(...) bytes long.
	@param qr The QueryResult to marshall
	@param q The query corresponding to the query result
	@param bytes The byte array to write the result into.
	
    */
    command TinyDBError toBytes(QueryResultPtr qr, ParsedQueryPtr q, CharPtr bytes);
    
    /** Convert a set of bytes into a query result
	@param bytes The byte array containing the bytes to convert
	@param qr The QueryResult to create (WARNING: may contain pointers into bytes!)
	@param q The ParsedQuery that corresponds to the bytes / qr
    */
    command TinyDBError fromBytes(QueryResultPtr bytes, QueryResultPtr qr, ParsedQueryPtr q);


    /** Create a QueryResult from a ResultTuple */
    command TinyDBError fromResultTuple(ResultTuple r, QueryResultPtr qr, ParsedQueryPtr pq);
    
    /** Return the queryId corresponding to the specified QueryResult network message */
    command uint8_t queryIdFromMsg(QueryResultPtr qr);


    /** @return The number of fields in this result */
    command short numRecords(QueryResultPtr qr, ParsedQueryPtr q);

    /** @return The specified sub result from this query result (will contain references into qr)
	@param i The result number to retrieve (0 .. numRecords) 
	@param q The query corresponding to this query result
    */
    command ResultTuple getResultTuple(QueryResultPtr qr, short i, ParsedQueryPtr q);


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
    command TinyDBError addAggResult(QueryResultPtr qr, int16_t groupNo, char *bytes, int16_t size, ParsedQueryPtr q, short exprIdx);

    //note that we do not provide methods to automatically convert query results to / from network messages

}

    
