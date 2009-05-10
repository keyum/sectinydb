// $Id: ParsedQueryIntf.nc,v 1.3 2003/10/07 21:46:20 idgay Exp $

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
includes TinyDB;

/** The ParsedQueryIntf is used for interacting with ParsedQueries (e.g.
	Queries whose fields have been converted into schema indices)	
    This is the primary way in which most of TinyDB Interacts with queries --
    routines are provided to get and set expressions and fields, and also
    to map from named fields into offsets in results for queries

	@author Sam Madden (madden@cs.berkeley.edu)
*/	
interface ParsedQueryIntf {
  /** @return true iff the specified field is null */
  command bool queryFieldIsNull(uint8_t field);

  /** @return true iff the specified field is a typed field (e.g. doesn't map
	directly to a schema field)
   */
  command bool queryFieldIsTyped(uint8_t field);

  /** @return the nth expression in the parsed query */
  command Expr getExpr(ParsedQueryPtr q, uint8_t n);

  /** @return a pointer to the nth expression in the parsed query */
  command ExprPtr getExprPtr(ParsedQueryPtr q, uint8_t n);

  /** @return the nth field in the parsed query */
  command uint8_t getFieldId(ParsedQueryPtr q, uint8_t n);

  /** Set the nth expression in the parsed query */
  command result_t setExpr(ParsedQueryPtr q, uint8_t n, Expr e);

  /** @return a pointer to the start of the tuple stored in a parsed query */
  command TuplePtr getTuplePtr(ParsedQueryPtr q);

  /** @return the size of the parsed query excluding the tuple data corresponding
	to the specified QueryPtr (used to allocate a parsed query) */
  command short baseSize(QueryPtr q);


  /*# @return the size of the parsed query excluding the tuple data */
  command short pqSize(ParsedQueryPtr q);

  /** @return the number of fields in results from this query.  Note that
     this is either the number of fields in tuples for this query or the
     number of aggregate expressions, depending on whether any aggregate
     expressions exist.
	@param agg (on return) Whether there are aggregate results in this query
	
  */
  command uint8_t numResultFields(ParsedQueryPtr q, bool *agg);
  
  /** Copy data from the field resultid (as returned by getResultId) of qr into result_buf
	@param q The query that qr belongs to
	@param qr The QueryResult to copy data from
	@param resultid The index of the desired field from qr
	@param result_buf (on return) Data from the specified field will be copied into this buffer
	       Note that no  bounds checking is performed -- insure that result_buf is at least big
	       enough to hold the result -- if this is a Tuple field, see TupleIntf.fieldSize(...).  If it
	       is an aggregate field, see AggOperator.finalizeAggExpr
	@return err_InvalidIndex if the specified resultid is not valid
   */
  command TinyDBError getResultField(ParsedQueryPtr q, QueryResultPtr qr, uint8_t resultid, char *result_buf);
  
  /** Return the index (to be used in getResultField) of the field corresponding to f 
     in this quey.
     @param q The query to which f belongs
     @param f The field to look for
     @param id (on return) The id of the field f (if it exists)
     @return err_InvalidIndex if the query does not contain a corresponding field
  */
  command TinyDBError getResultId(ParsedQueryPtr q, Field *f, uint8_t *id);

  /** Verify that the schema of the destination query matches the
      schema of the select query.  The dest query must create a buffer and
      have a table of named fields set up.  The number, order, and type of
      these fields must match the fields in the select query.
      @param dest A ParsedQuery with a Table of named, typed fields
      @param select A ParsedQuery that will insert into dest
  */
  command bool typeCheck(ParsedQuery *dest, ParsedQuery *select);

  /** Return the type of the specified field index from 
      pq in type.  Return FAIL if the index is invalid,
      or the field is NULL.
      @param pq The query to get the field type from
      @param fieldIdx The index of the field whose type is desired
      @param type (on return) The type of the requested field
      @return FAIL if the index is valid or the field is NULL
  */
  command result_t getFieldType(ParsedQuery *pq, uint8_t fieldIdx,
						uint8_t *type);



} 
