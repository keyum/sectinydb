// $Id: AggOp.java,v 1.20 2003/10/07 21:46:07 idgay Exp $

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

/**
 * Combines AggregateEntry from catalog with some constant aguments.
 * Delegates most functionality to aggregate entry
 */

public class AggOp {

	public static final byte AGG_NOOP = 0;
	/*
    public static final byte AGG_SUM = 0;
    public static final byte AGG_MIN = 1;
    public static final byte AGG_MAX = 2;
    public static final byte AGG_COUNT = 3;
    public static final byte AGG_AVERAGE = 4;
	public static final byte AGG_MIN3 = 5;
    public static final byte AGG_EXPAVG = 7;
    public static final byte AGG_WINAVG = 8;
    public static final byte AGG_WINSUM = 9;
    public static final byte AGG_WINMIN = 10;
    public static final byte AGG_WINMAX = 11;
    public static final byte AGG_WINCNT = 12;
    public static final byte AGG_DELTA = 13;
    public static final byte AGG_TREND = 14;
    public static final byte AGG_WINRAND = 15;
    public static final byte AGG_ADPDELTA = 16;
	 */

	
	/**
	 * Constructs AggOp object for an aggregate with a given name.
	 * This aggregate must have been registered with the catalog
	 * @param argList list of arguments (mostly for temporals), null if none
	 * Arguments currently are restricted to Integers (as per parser)
	 */
    public AggOp(String name, List argList)
		throws IllegalArgumentException {
       	
		AggregateEntry agg =
			Catalog.currentCatalog().getAggregateCatalog().getAggregate(name);
		
		if (name == null)
			throw new IllegalArgumentException("No aggegate " + name + " in catalog");
		
       	myAggregate = agg;
       	myArgs = (argList == null ) ? Collections.EMPTY_LIST : argList;
		
		AggregateArgumentValidator validator;
		try {
			validator = (AggregateArgumentValidator)Class.forName(agg.getValidatorClassName()).newInstance();
		} catch (Exception e) {
			throw new IllegalArgumentException("Invalid aggregate");
		}
		
		validator.validate(this);//not inside a try/catch b/c want the IllegalArgumentException to propagate
		
		try {
			myReader = (AggregateResultsReader)Class.forName(agg.getReaderClassName()).newInstance();
		} catch (Exception e) {
			throw new IllegalArgumentException("Invalid aggregate");
		}
    }
    
	/**
	 * Constructs AggOp object for an aggregate with a given name.
	 * This aggregate must have been registered with the catalog
	 * and must take no arguments
	 */
    public AggOp(String name) throws IllegalArgumentException {
      	this(name, null);
    }
	
	/**
	 * @return type (opcode) for this aggregate
	 */
    public byte toByte() {
	    return (byte)myAggregate.type();
    }

	/**
	 * @returns indexth argument, index is zero-based
	 * @throws IndexOutOfBoundsException if index is illegal
	 */
	public short getArgument(int index) throws IndexOutOfBoundsException {
		return 	((Integer)myArgs.get(index)).shortValue();
	}
	
	/**
	 * @deprecated
	 */
    public short getConst1() {
	    return getArgument(0);
    }
	
	/**
	 * @deprecated
	 */
    public short getConst2() {
	    return getArgument(1);
    }

	/**
	 * @deprecated
	 */
    public short getConst3() {
	    return getArgument(2);
    }
	
	public List getArguments() { return myArgs; }

    public boolean isTemporal() {
        return myAggregate.isTemporal();
    }

    public String toString() {
        return myAggregate.toString();
    }

    public String getValue() {
        return myReader.getValue();
    }
	
	public void read(byte[] data) {
		myReader.read(data);
	}
	
	public void finalizeValue() {
		myReader.finalizeValue();
	}
	
	public void copyResultState(AggOp agg) {
		myReader.copyResultState(agg.getReader());
	}
	
	public AggregateResultsReader getReader() {
		return myReader;
	}
	
	
	protected List                   myArgs;//list of arguments
    
    protected AggregateEntry         myAggregate;
	protected AggregateResultsReader myReader;
}

