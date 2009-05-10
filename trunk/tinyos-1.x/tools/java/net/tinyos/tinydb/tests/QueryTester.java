// $Id: QueryTester.java,v 1.4 2003/10/07 21:46:08 idgay Exp $

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

import java.util.*;
import java.io.IOException;

/**
 * This is the main test suite. It runs all parsable queries in the catalog
 * for specfied number of epochs, waits a specified period of time for
 * results to come, and checks results against expected result tuples specifed
 * in the test case.
 *
 * NOTE: This assumes that TinyDBMain.initMain() has been called
 *
 * @author Eugene Shvets
 */
public class QueryTester extends TestCase {
	
	/**
	 * Constructs QueryTester for a specified test query;
	 *
	 * @param query the test query
	 * @param reset if true, resets the network before the query
	 */
	QueryTester(TestQuery query, boolean reset) {
		myQuery = query;
		myReset = reset;
	}
		
	
	protected void setUp() {
		if (myReset) {
			//reset DB
			try {
				TinyDBMain.mif.send((short)-1,CommandMsgs.resetCmd((short)-1));
			} catch (java.io.IOException e) {
		   		fail("Could not reset network");
			}
		}
	}
		
	
	/**
	 * Injects a single query into the network,
	 *  runs it for a specified number of epochs,
	 *  and checks results each epoch
	 */
	public synchronized void runTest() {
		System.out.println("##################");
		System.out.println("Testing query [" + myQuery.getQueryString()
										  + "] with wait time " + myQuery.getWaitingTime());
		
		TestQueryListener listener = new TestQueryListener(TinyDBMain.network,
												       	myQuery,
														this);
		try {
			wait(myQuery.getWaitingTime());
		} catch (InterruptedException e) {
			System.out.println("testSingleQuery waiting is interrupted!!!");
		}
		
		//were woken up or interrupted
		if (!listener.queryCompleted()) { //we were not woken up by the listener
			assertTrue("Failed to get result from the query: " + myQuery.getQueryString(), false);
		}
		
		System.out.println("...completed with result: " + listener.getResults() );
		
		//check the actual result against expected, if needed
		if (myQuery.isResultMatchRequested()) {
			for(int epoch=1; epoch<=myQuery.getEpochsToRun(); epoch++) {
				boolean match =
					myQuery.matchResult(epoch, listener.getResult(epoch));
				assertTrue("Result mismatch. Expected result: " + myQuery.getExpectedResult(epoch) +
							   ". Actual result: " + listener.getResult(epoch), match);
						
			}
		}
			
	}
	
	TestQuery myQuery;
	boolean myReset;//reset network before executing this query
	
	private static final boolean DEBUG = true;
}

