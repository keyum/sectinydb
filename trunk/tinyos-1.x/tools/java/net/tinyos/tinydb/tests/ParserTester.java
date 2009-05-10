// $Id: ParserTester.java,v 1.2 2003/10/07 21:46:08 idgay Exp $

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
package net.tinyos.tinydb.tests;

import junit.framework.*;
import net.tinyos.tinydb.*;
import net.tinyos.tinydb.parser.*;

import java.io.*;
import java.util.List;

/**
 * This suite tests the parsing of the queries without injecting them
 *
 * @author Eugene Shvets 1/29/03
 */
public class ParserTester extends TestCase {

	List goodQueries, badQueries;
	
	TinyDBNetwork network;
	TinyDBQuery query;
	
	protected void setUp() {
		goodQueries = TestCatalog.getTestCatalog().getParsableQueries();
		badQueries = TestCatalog.getTestCatalog().getUnparsableQueries();
		
		//initialize DB
 		try {
			TinyDBMain.initMain();
		} catch (IOException e) {
			System.out.println("TinyDBMain.initMain failed.");
			System.exit(1);
		}
	}
	
	public static Test suite() {
		return new TestSuite(ParserTester.class);
	}
	
	public void testGoodQueries() {
		for(int i=0; i<goodQueries.size();i++) {
			byte qid = MainFrame.allocateQID();
			String queryString = ((TestQuery)goodQueries.get(i)).getQueryString();
			try {
				query = SensorQueryer.translateQuery( queryString, qid);
			} catch (ParseException e) { //fail the test if parse fails
				fail("Failed parsing query: " + queryString +
						 "\nwith message " + e.getMessage());
			}
			
		}//for
	}
	
	public void testBadQueries() {
		for(int i=0; i<badQueries.size();i++) {
			byte qid = MainFrame.allocateQID();
			String queryString = ((TestQuery)badQueries.get(i)).getQueryString();
			try {
				query = SensorQueryer.translateQuery(queryString, qid);
				// fail the test if parse succeeds
				if (query != null) fail("Succeeded parsing query: "
											+ queryString +"\nExpected to fail" );
			} catch (ParseException e) {
				// correctly failed parsing query
			}
			
		}//for
	}
	
	public static void main (String[] args) {
		junit.textui.TestRunner.run(suite());
	}
}
