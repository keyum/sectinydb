// $Id: AggregateResultsReader.java,v 1.5 2003/10/07 21:46:07 idgay Exp $

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

/**
 * This interface interprets data read from QueryResultMessage
 * in an aggregate-specific way; calculates the final value
 * of the aggregate; and provides access to this value
 * through getValue accessor
 *
 * @author Eugene Shvets
 * @version 1.0, October 23, 2002
 *
 *
 * Changed 11.3.2002 to use objects for state.  SRM.
 */
public interface AggregateResultsReader {
	
	
	/**
	 * Reads data from the raw byte result data
	 */
    public void read(byte[] data);
	
	/**
	 * Calculates final value of the aggregate
	 * This value can be fetched via getValue
	 */
	public void finalizeValue();
	
	/**
	 * Returns a string representation of the finalized value
	 * @return string representation of the finalized value
	 */
	public String getValue();
	
	/**
	 * Copies result state of this reader into argument reader
	 * @throws IllegalArgumentException if reader is of a wrong class
	 */
	public void copyResultState(AggregateResultsReader reader) throws IllegalArgumentException;
}
