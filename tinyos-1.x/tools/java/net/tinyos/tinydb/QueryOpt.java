// $Id: QueryOpt.java,v 1.2 2003/10/07 21:46:07 idgay Exp $

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
package net.tinyos.tinydb;

import java.util.*;
import java.math.*;

public class QueryOpt {
    /** Given a query, reorder the expressions in it based on 
	selectivity estimates from the catalog.

	At this point, optimization is very primitive;  we assume
	attributes are uniformly distributed over a specified
	range.  We do not perform acqusitional optimization (e.g.
	interleave sampling and application of selection), and also
	do no perform push-down from aggregates into the queries
	themselves.
    */
    public static void optimizeQuery(Catalog cat, TinyDBQuery query) {
	if (query.numSelExprs() <= 0) return;
	
	//walk through the expressions, and reorder them based on
	//the estimated selectivities
	QueryExpr curExpr;
	Vector reordered = new Vector();
	float sels[] = new float[query.numSelExprs()];
	
	if (TinyDBMain.debug) System.out.println("Optimizing query;  initial order:");
	for (int i = 0; i < query.numSelExprs(); i++) {
	    curExpr = query.getSelExpr(i);
	    if (TinyDBMain.debug) System.out.println("Expr " + i + " : " + curExpr.toString());
	    sels[i] = estimateSelectivity(cat, curExpr);
	    reordered.addElement(curExpr);
	}
	
	//selection sort, from lowest to highest selectivity
	for (int i = 0; i < sels.length-1; i ++) {
	    float max = Float.MIN_VALUE, tmp;
	    int max_idx = 0;
	    for (int j = i; j < sels.length; j++) {
		if (sels[j] > max) {
		    max_idx = j;
		    max = sels[j];
		}
	    }
	    
	    tmp = sels[i];
	    sels[i] = sels[max_idx];
	    sels[max_idx] = tmp;
	    
	    curExpr = (QueryExpr)reordered.elementAt(i);
	    reordered.set(i, reordered.elementAt(max_idx));
	    reordered.set(max_idx, curExpr);
	    
	}
	
	for (int i = 0; i < reordered.size(); i++) {
	    if (TinyDBMain.debug) System.out.println("Expr : " + reordered.elementAt(i) + ", selectivity : " + sels[i]);
	}
	
	//and replace them
	query.setSelExprs(reordered);
    }

    /** Given a QueryExpression and the catalog with metadata about the fields
	in that expression, estimate the selectivity of the expression.
	@param cat The catalog containing metadata about the expression
	@param expr The expression whose selectivity we want to compute
    */
    public static float estimateSelectivity(Catalog cat, QueryExpr expr) {
      QueryField qf = cat.getAttr(expr.getField());
      SelExpr se = (SelExpr)expr;
      float min = qf.getMinVal(),
	  max = qf.getMaxVal(); 

      float value = computeValue(se.getFieldConst(), se.getFieldOp(), se.getValue());
      float range = (max - min) + 1f;

      /* 
	 Compute the selectivity of each selection expression based on the
	 operator in the expression, the constant value on the right hand
	 side of the expression, and the range ({min .. max}) of the attribute on the
	 left hand expression.

	 Note that we assume query expressions are of the form:

	 attr ARITHOP const1 RELOP const2

	 where attr has range [min ... max]

	 And that we reduce such expressions, using computeValue(...) to
	 
	 attr RELOP (const2 INV(ARITHOP) const1)
	 with range [(min INV(ARITHOP) const1) ... (min INV(ARITHOP) const1)]

	 Note that if an attribute is constant, we can't use that information
	 here unless we know exactly what it's constant value is, which we currently
	 don't.  This might be an insentive for doing mote-side query optimization.
      */
      switch (se.getSelOpCode()) {
      case SelOp.OP_EQ:
	  if (value < min || value > max) return 1.0f;  //can't possibly be true
	  else return (1f- 1.0f/range); //assume integer units
      case SelOp.OP_NEQ: //NEQ is 1-EQ
	  if (value < min || value > max) return 0f; //always true
	  else return (1.0f/range);
      case SelOp.OP_GT:
	  if (value < min ) return 0f; //always true
	  if (value >= max) return 1f; //never true
	  else return (value - min)/range;

      case SelOp.OP_GE:
	  if (value <= min ) return 0f; //always true
	  if (value > max) return 1f; //never true
	  else return ((value - min)+1)/range;

      case SelOp.OP_LT:
	  if (value <= min ) return 1f; //never true
	  if (value > max) return 0f; //always true
	  else return (max - value)/range;
      case SelOp.OP_LE:
	  if (value < min ) return 1f; //never true
	  if (value >= max) return 0f; //always true
	  else return ((max - value) + 1)/range;

      default:
	  return 0.5f; //something reasonable?
      }

  }
    
    
    /** Given a selection expression, invert whatever arithmetic
	may be applied to the field value to determine the
	value of this constant.
	
	Assumes that the se has a specific form;  namely,
	
	field arithOp const1 relOp const2
	
	The return value will be

	const2 inv(arithOp) const1

    */
    private static float computeValue(float const1, int arithOp, float const2) {


	switch (arithOp) {
	case ArithOps.NO_OP:
	    return const2;
	case ArithOps.MULTIPLY:
	    return const2/const1;
	case ArithOps.DIVIDE:
	    return const2 * const1;
	case ArithOps.ADD:
	    return const2 - const1;
	case ArithOps.SUBTRACT:
	    return const2 + const1;
	case ArithOps.SHIFT_RIGHT:
	    return const2 * (float)Math.pow(2, const1); //shift left == multiply by 2^const1
	}
	return const2;

    }
    
}

