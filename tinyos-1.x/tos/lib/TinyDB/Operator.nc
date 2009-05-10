// $Id: Operator.nc,v 1.2 2003/10/07 21:46:20 idgay Exp $

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

/** Operators apply filters and transformations to data tuples and
    neighbor results.  They are applied by the TupleRouter. Examples
    of operators include selections and aggregates (both of which
    implement the operator interface.
    
    Due to the fairly static nature of TinyDB, support for Selections
    and Aggregates are currently hard coded -- e.g., to add new operator
    types, explicit changes to the TupleRouter are needed.
*/
interface Operator
{
  /** Process a tuple produced locally 
     @param qs The query the tuple belongs to
     @param The tuple
     @param The expression to apply to the tuple
     @return Error code indicating failures (if any)
  */
  command TinyDBError processTuple(ParsedQueryPtr qs, TuplePtr t, ExprPtr e);

  /** Check to see if this the result qr is a result from the application of expression e
      @param qr The query result
      @param e The expression to check
   */
    command bool resultIsForExpr(QueryResultPtr qr, ExprPtr e);

    /** Return the next result for this expression
       @param qr (input) The index of the result to return <br> 
                 (output) The value of the result
       @param qs The query whose results we are fetching
       @param e The expressions whose results we are fetching       

       Note that stateless operators (e.g. filters) may not return any results
  */
  command TinyDBError nextResult(QueryResultPtr qr, ParsedQueryPtr qs, ExprPtr e);

  /** Process a tuple from a neighbor 
   @param qr The result to process
   @param qs The query corresponding to the result
   @param e The expression corresponding to the result
   @return Error code indicating type of failure.  Expect err_InvalidAggregateRecord if qs or
    e don't correspond to qr.
  */
  command TinyDBError processPartialResult(QueryResultPtr qr, ParsedQueryPtr qs, ExprPtr e);

  /** Signal to the operator that an epoch as ended, possibly causing it to reset the 
      state that this operator stores for the specified expression 
      (Called every epoch)
      Operator state is appended to the expression (ick!) , in the opState handle --
      each expression is owned by exactly one operator, which may store state there.
      @param q The query that's being reset
      @param e The expression that's being reset
  */ 
  command result_t endOfEpoch(ParsedQueryPtr q, ExprPtr e);


  /** Called when an operator has finished processing a remote result */
  event TinyDBError processedResult(QueryResultPtr qr, ParsedQueryPtr q, ExprPtr e);

  /** Called when an operator has finished processing a local tuple
     @param t The tuple just processed. 
     @param q The query the tuple belongs to 
     @param e The expression that was applied.  If e is a filter (selection operator)
     e->passed indicates if this tuple passed the filter.
     @param passed True if this tuple passed the operator and should continue to be processed
  */
  event TinyDBError processedTuple(TuplePtr t, ParsedQueryPtr q, ExprPtr e, bool passed);
}

    
