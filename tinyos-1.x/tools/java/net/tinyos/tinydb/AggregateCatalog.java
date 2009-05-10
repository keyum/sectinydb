// $Id: AggregateCatalog.java,v 1.6 2003/10/07 21:46:07 idgay Exp $

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

import java.util.HashMap;
import java.util.Collection;

public class AggregateCatalog {
    
	/**
	 * Constructs an empty AggregateCatalog
	 */
    AggregateCatalog() {
        aggregates = new HashMap();
		code2NameMap = new HashMap();
    }
    
	/**
	 * Registers a new aggregate
	 */
    public void registerAggregate(int code, String name, boolean isTemporal, int argCount, String readerClass, String validatorClass)
    throws InvalidAggregateDefinitionException {
        aggregates.put(name.toUpperCase(),
					   new AggregateEntry(code, name, isTemporal, argCount, readerClass, validatorClass));
		code2NameMap.put(new Integer(code), name.toUpperCase());
    }
	
    
	/**
	 * @returns AggregateEntry representing the aggregate with a given name
	 * if one is registered with this catalog; otherwise null
	 */
    public AggregateEntry getAggregate(String name) {
		
		if (DEBUG) {
			System.out.println("Requested aggregete " + name);
			System.out.println("Catalog contents: " + aggregates.keySet());
		}
        return (AggregateEntry)aggregates.get(name.toUpperCase());
    }
	
    
    /**
	 * Returns collection of all AggregateEntries
	 * registered with the catalog
	 */
    public Collection getAggregates() {
        return aggregates.values();
    }
	
	/**
	 * @returns name of aggregate with given code
	 */
	public String getAggregateNameFor(int code) {
		return (String)code2NameMap.get( new Integer( code));
	}
		
    
    /**
     * Returns all registered agg types as a set of Integers
     
    public Set getAggregateTypes() {
        return aggregates.keySet();
    } */
    
    private HashMap aggregates;//maps name -> AggregateEntry
	private HashMap code2NameMap;//maps code -> name
	
	private static final boolean DEBUG = false;
}
