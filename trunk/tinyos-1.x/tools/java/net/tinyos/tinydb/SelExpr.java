// $Id: SelExpr.java,v 1.3 2003/10/07 21:46:07 idgay Exp $

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

/** SelExpr represents a selection expression;  selection expressions are of
    the form:

    WHERE (field fieldOp fieldConst) OP value
    
    Where field is a field in the query, value is an integral value,
    and op is a SelOp.
*/
public class SelExpr implements QueryExpr {
    public SelExpr(short field, SelOp op, short value) {
	this.field = field;
	this.op = op;
	this.value = value;

	this.fieldOp = ArithOps.NO_OP;
	this.fieldConst = 0;
    }

    public SelExpr(short field, String fieldOp, short fieldConst, SelOp op, short value) {
	this.field = field;
	this.fieldOp = ArithOps.getOp(fieldOp);
	this.fieldConst = fieldConst;
	this.op = op;
	this.value = value;
    }

    public SelExpr(short field, SelOp op, String stringConst) {
	this.isString = true;
	this.op = op;
	if (stringConst.length() > MAX_STRING_LEN)
	    this.stringConst = stringConst.substring(0,MAX_STRING_LEN);
	else
	    this.stringConst = stringConst;
	this.field = field;
    }

    public boolean isAgg() {
	return false;
    }
    public short getField() {
	return field;
    }

    public short getValue() {
	return value;
    }

    public short getFieldConst() {
	return fieldConst;
    }

    public String getStringConst() {
	return stringConst;
    }

    public short getFieldOp() {
	return fieldOp;
    }
    
    public byte getSelOpCode() {
	return op.toByte();
    }

    public String toString() {
	return ("SelOp( (" + field + " " + ArithOps.getStringValue(fieldOp) + " " + fieldConst + ") " + op + " " + value + ")\n");
    }

    public boolean isString() {
	return isString;
    }
    
    private short fieldConst = 0;
    private short fieldOp = 0;

    private short field = 0;
    private SelOp op;
    private short value = 0;
    private String stringConst = "";
    private boolean isString = false;
    static final int MAX_STRING_LEN=7;

}
