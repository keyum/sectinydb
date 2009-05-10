// $Id: AggExpr.java,v 1.4 2003/10/07 21:46:07 idgay Exp $

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

/** Class to represent an aggregation expression.
 Aggregates are of the form:
 [aggf(fielda),groupby(fieldb)]
 
 Aggf is an aggregation function from AggOp,
 and groupby may be NO_GROUPING, indicating an ungrouped aggregate
 */
public class AggExpr implements QueryExpr {
    public static final short NO_GROUPING = (short)0xFFFF;
	
    /** Create an aggregate expression applying the specified
	 operation to field, grouping by field groupBy.
	 @param field The field to aggregate
	 @param op The operator to aggregate with
	 @param groupBy The field to group by, or NO_GROUPING
	 */
    public AggExpr(short field, AggOp op, short groupBy) {
		this.field = field;
		this.op = op;
		this.groupBy = groupBy;
    }
	
    /** Create an aggregate expression that applies a simple arithmetic
	 expression to the field before applying the aggregate operator
	 */
    public AggExpr(short field, String fieldOp, short fieldConst, AggOp op, short groupBy) {
		this.field = field;
		this.fieldOp = ArithOps.getOp(fieldOp);
		this.fieldConst = fieldConst;
		this.op = op;
		this.groupBy = groupBy;
    }
	
    /** Create an aggregate expression and set the groupBy field
	 later.  Added by Kyle
	 */
    public AggExpr(short field, AggOp op) {
		this.field = field;
		this.op = op;
		this.groupBy = -1;
    }
	
    public AggExpr(short field, String fieldOp, short fieldConst, AggOp op) {
		this.field = field;
		this.fieldOp = ArithOps.getOp(fieldOp);
		this.fieldConst = fieldConst;
		this.op = op;
		this.groupBy = -1;
    }
	
    public boolean isAgg() {
		return true;
    }
	
    public boolean isTemporalAgg() {
		return op.isTemporal();
    }
    
    public short getField() {
		return field;
    }
	
    public short getGroupField() {
		return groupBy;
    }
    
    // added by Kyle
    public void setGroupField(short groupBy) {
		this.groupBy = groupBy;
    }
	
    public byte getAggOpCode() {
		return op.toByte();
    }
    
    public AggOp getAgg() {
		return op;
    }
	
	/** groupFieldOp is a constant representing a simple arithmetic operator
	 that will be performed on the value of the group by attribute before
	 the groups are defined.
	 */
	public short getGroupFieldOp() {
		return groupFieldOp;
	}
	
	public void setGroupFieldOp(String groupFieldOpStr) {
		groupFieldOp = ArithOps.getOp(groupFieldOpStr);
	}
	
	/** groupFieldConst is a constant value that is used inthe arithmetic operation
	 specified by groupFieldOp
	 */
	public short getGroupFieldConst() {
		return groupFieldConst;
	}
	
	public void setGroupFieldConst(short groupFieldConst) {
		this.groupFieldConst = groupFieldConst;
	}
	
    /** fieldOp is a constant representing a simple arithmetic operator
	 that will be performed on the value of the attribute before the
	 aggregate is computed.
	 */
    public short getFieldOp() {
		return fieldOp;
    }
	
	public void setFieldOp(String fieldOpStr) {
		this.fieldOp = ArithOps.getOp(fieldOpStr);
	}
    
	
    /** fieldConst is the constant in the arithmetic operation specified by fieldOp */
    public short getFieldConst() {
		return fieldConst;
    }
	
	public void setFieldConst(short fieldConst) {
		this.fieldConst = fieldConst;
	}
	
    public String toString() {
		return("Agg:  " + op + "(" + field + " " + ArithOps.getStringValue(fieldOp) + " " + fieldConst + " " + op.getArguments() + ")  Group By(" + groupBy + " " + ArithOps.getStringValue(groupFieldOp) + " " + groupFieldConst + ")\n");
    }
	
	
	private short fieldOp = ArithOps.NO_OP; // By default, there is no operation applied to the aggregated field
	private short fieldConst = 0;
	private short field; //the id of the field the aggregate pertains to
	private AggOp op;
	private short groupBy = NO_GROUPING;
	private short groupFieldOp = ArithOps.NO_OP; // By default, there is no operation applied to the group by field
	private short groupFieldConst = 0;
}
