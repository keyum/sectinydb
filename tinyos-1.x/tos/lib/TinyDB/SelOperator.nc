// $Id: SelOperator.nc,v 1.3 2003/10/07 21:46:21 idgay Exp $

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



module SelOperator {
  provides {
    interface Operator;
  }

  uses {
    interface TupleIntf;
    interface ExprEval;
  }
}

implementation
{
  ParsedQuery *mQs;
  Tuple *mT;
  Expr *mE;

  task void doFilter();

  /* Process a tuple produced locally 
     qs: The query the tuple belongs to
     t: The tuple
     e: The expression to apply to the tuple
    */
  command TinyDBError Operator.processTuple(ParsedQueryPtr qs, TuplePtr t, ExprPtr e) {
    mQs = qs;
    mT = t;
    mE = e;

    post doFilter();

    return err_NoError;
  }



  task void doFilter() {
    ParsedQuery *qs = mQs;
    Tuple *t = mT;
    Expr *e = mE;
    OpValExpr ex;
    short size;
    char *fieldBytes;
    short fieldVal = 0;
    short i;
    bool result = FALSE;
    

    if (! e->isStringExp) {
      ex = e->ex.opval;
      size = call TupleIntf.fieldSize(qs, (char)ex.field);
      fieldBytes = call TupleIntf.getFieldPtr(qs, t, (char)ex.field);
      
      
      for (i = 0; i < size; i++) {
	unsigned char b = (*fieldBytes++);
	fieldVal += ((unsigned short)b)<<(i * 8);    
      }
      
      fieldVal = call ExprEval.evaluate(e, fieldVal);
      
      switch (ex.op) {
      case EQ:
	result = (fieldVal == ex.value);
	break;
      case NEQ:
	result = (fieldVal != ex.value);
	break;
      case GT:
	result = (fieldVal > ex.value);
	break;
      case GE:
	result = (fieldVal >= ex.value);
	break;
      case LT:
	result = (fieldVal < ex.value);
	break;
      case LE:
	result = (fieldVal <= ex.value);
	break;
      }
    } else {
      //handle string comparison separately
      StringExpr sex = e->ex.sexp;
      int strCmpVal;
      dbg(DBG_USR2, "evaluation string expression!");
      size = call TupleIntf.fieldSize(qs, (char)sex.field);
      fieldBytes = call TupleIntf.getFieldPtr(qs, t, (char)ex.field);
      strCmpVal = strcmp(sex.s, fieldBytes);
      if (strCmpVal == 0) {
	result = (sex.op == LE || sex.op == EQ || sex.op == GE);
      } else if (strCmpVal < 0) {
	result = (sex.op == GT || sex.op == GE || sex.op == NEQ);
      } else result = (sex.op == LT || sex.op == LE || sex.op == NEQ);
      
    }

    signal Operator.processedTuple(t,qs,e,result);
  }

    /* Return the next result for this expression
       qr (input):  The index of the result to return
       qr (output):  The value of the result
       qs: The query whose results we are fetching
       e: The expressions whose results we are fetching
       
       Note that stateless operators (e.g. filters) may not return any results
    */
  command TinyDBError Operator.nextResult(QueryResultPtr qr, ParsedQueryPtr qs, ExprPtr e) {
    return err_NoMoreResults;
  }

  
  //not implemented
  command TinyDBError Operator.processPartialResult(QueryResultPtr qr, ParsedQueryPtr qs, ExprPtr e) {
    return err_NoError;
  }

    /* Not Implemented
    */ 
  command result_t Operator.endOfEpoch(ParsedQueryPtr q, ExprPtr e) {
    return SUCCESS;
  }

  command bool Operator.resultIsForExpr(QueryResultPtr qr, ExprPtr e) {
    if (qr->qrType != kNOT_AGG) return FALSE;
    return TRUE;
  }


}

    
