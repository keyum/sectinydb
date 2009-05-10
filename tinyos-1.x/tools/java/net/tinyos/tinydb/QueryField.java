// $Id: QueryField.java,v 1.12 2003/10/07 21:46:07 idgay Exp $

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

/** Class representing a named field in a query */
public class QueryField implements Cloneable {
    private String name;
    private String alias = "";
    private String table;
    private byte type;
    private short idx = -1;
    private byte op;
    private float cost = 0.0f;
    private float min = 0.0f, max = 1024.0f;
    private boolean isConstant = false;

    public static final byte INTONE = 1;
    public static final byte UINTONE = 2;
    public static final byte INTTWO = 3;
    public static final byte UINTTWO = 4;
    public static final byte INTFOUR = 5;
    public static final byte UINTFOUR = 6;
    public static final byte TIMESTAMP = 7;
    public static final byte STRING= 8;
    public static final byte BYTES = 9;
    public static final byte COMPLEX_TYPE = 10;
    public static final byte UNKNOWN_TYPE=11;
    
  public QueryField(String field, byte fieldType, int min, int max) throws NoSuchElementException {
      this(field,fieldType);
      this.min = (float)min;
      this.max = (float)max;

  }

  public QueryField(String field, byte fieldType) throws NoSuchElementException {
     if (field.indexOf(".") != -1) {
	    table = field.substring(0, field.indexOf("."));
	    name = field.substring(field.indexOf(".")+1);
     } else {
	        name = field;
	        table = null;
     }
    if (fieldType < INTONE || fieldType > UNKNOWN_TYPE)
       throw new NoSuchElementException();
       
    type = fieldType;
    op = AggOp.AGG_NOOP;
  }

  public QueryField(String field, String alias, byte fieldType) throws NoSuchElementException {
     if (field.indexOf(".") != -1) {
	    table = field.substring(0, field.indexOf("."));
	    name = field.substring(field.indexOf(".")+1);
     } else {
	        name = field;
	        table = null;
     }
    if (fieldType < INTONE || fieldType > UNKNOWN_TYPE)
       throw new NoSuchElementException();
    setAlias(alias);
    type = fieldType;
    op = AggOp.AGG_NOOP;
  }

    public short getIdx() {
	    return idx;
    }

    public void setIdx(short idx) {
	    this.idx = idx;
    }
  
    public String getName() {
	    return name;
    }
    
    public byte getType() {
	    return type;
    }
    
    public void setType(byte type) {
	    this.type = type;
    }

    public String getAlias() {
	return alias;
    }

    public void setAlias(String s) {
	alias = s;
    }
    

    public void setCost(float cost) {
	this.cost = cost;
    }

    public float getCost() {
	return cost;
    }

    public void setMinVal(float min) {
	this.min = min;
    }

    public float getMinVal() {
	return min;
    }

    public void setMaxVal(float max) {
	this.max = max;
    }

    public float getMaxVal() {
	return max;
    }

    public void setIsConstant(boolean isConstant) {
	this.isConstant = isConstant;
    }

    public boolean getIsConstant() {
	return isConstant;
    }
    
    public byte getOp() { return op; }

    public void setOp(byte op) { this.op = op; }

    public String toString() {
	    if (op != AggOp.AGG_NOOP) {
	        try {
		        return getName() + " OP = " +
					Catalog.currentCatalog().getAggregateCatalog().getAggregateNameFor(op);
	        } catch (NoSuchElementException e) {
		        return getName();
	        }
	    }
	    else return getName();
    }

    public QueryField copy() {
	    try {
	        return (QueryField)this.clone();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
    }
  

}
