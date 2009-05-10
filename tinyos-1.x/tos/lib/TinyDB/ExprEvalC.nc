// $Id: ExprEvalC.nc,v 1.3 2003/10/07 21:46:20 idgay Exp $

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
/** Expression evaluator that allows for more complicated select and aggregate expressions.
 *  For example 	"select avg(s.temp * 2) from sensors as s
 *		 where s.temp / 5 > 25
 *		 group by s.light >> 2"
 *
 *  Author:  Kyle Stanek 
 *           Designed by Kyle Stanek and Sam Madden
 *  Created on July 15, 2002 at 3:52 PM
 * @author Kyle Stanek
 * @author Designed by Kyle Stanek and Sam Madden
 */ 

module ExprEvalC {
  provides {
    interface ExprEval;
  }
}

implementation
{
  // Prototype for local utility function
  short evaluateSimpleExpr(short a, short op, short b);
  
  command short ExprEval.evaluate(Expr *e, short fieldValue) {
    short fieldOp = e->fieldOp;
    short fieldConst = e->fieldConst;

    return evaluateSimpleExpr(fieldValue, fieldOp, fieldConst);
  }
  
  command short ExprEval.evaluateGroupBy(AggregateExpression a, short grpByFieldValue) {
    short grpByFieldOp = a.groupFieldOp;
    short grpByFieldConst = a.groupFieldConst;

    return evaluateSimpleExpr(grpByFieldValue, grpByFieldOp, grpByFieldConst);
  }

  command short ExprEval.evaluateSimple(short value, short op, short constVal) {
	return evaluateSimpleExpr(value,op,constVal);
  }
  
  //returns c, where c = a op b
  short evaluateSimpleExpr(short a, short op, short b) {
    
    //  Op codes are defined in TinyDB.h
    switch(op) { 
    case FOP_NOOP: //no op
      break;
    case FOP_TIMES:
      return (a * b); 
    case FOP_DIVIDE: 
      return (a / b); 
    case FOP_ADD: 
      return (a + b); 
    case FOP_SUBTRACT: 
      return (a - b); 
    case FOP_MOD: 
      return (a % b); 
    case FOP_RSHIFT: 
      return (a >> b); 
    }
    
    return a;
  }
}

