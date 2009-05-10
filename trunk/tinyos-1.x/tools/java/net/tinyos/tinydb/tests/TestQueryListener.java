// $Id: TestQueryListener.java,v 1.4 2003/10/07 21:46:08 idgay Exp $

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
/**
 * TestQueryListener.java
 *
 * @author Eugene Shvets 1/29/03
 */

package net.tinyos.tinydb.tests;

import net.tinyos.tinydb.*;
import net.tinyos.tinydb.parser.*;

import java.util.*;

/**
 * TestQueryListener injects a query into network and resets the network when the
 * first result arrives.
 */

public class TestQueryListener implements ResultListener {
	
	public static final short EXTRA_EPOCHS_TO_WAIT = 2;//results can interleave, so we
	//might want to wait a bit longer to ensure that all results for our epochs
	//have come
    
	/**
	 * Constructor -- runs the specified query using the
	 * provided network interface.
	 * @param nw A network interface for talking with the basestation /
	 *         parsing results.
	 * @param queryString the query to run.
	 * @param creator - object waiting to be notified when the query completes
	 */
    public TestQueryListener(TinyDBNetwork network, TestQuery query, Object creator) {
		myNetwork = network;
		myCreator = creator;
		myEpochsToRun = query.getEpochsToRun();
		
		myResults = new ArrayList( query.getEpochsToRun());//holds results for all epochs
		for(int i=0; i<query.getEpochsToRun(); i++) {
			myResults.add(new ArrayList());
		}
		
		try {
			myQuery = query.getTinyDBQuery();
			myQuery.setNumEpochs((short)(myEpochsToRun + EXTRA_EPOCHS_TO_WAIT));
			TinyDBMain.notifyAddedQuery(myQuery); // add query to list of known queries
			// set ourselves up to receives results for the query
			myNetwork.addResultListener(this, true, myQuery.getId());
			
			myNetwork.sendQuery(myQuery); //inject the query
			
			
		} catch (ParseException e) {
			System.err.println("Invalid query : " + query.getQueryString() + "(" + e.getMessage() + ")");
			System.err.println(SensorQueryer.errorMessage);
		} catch (java.io.IOException e) {
			System.err.println("Network error: " + e);
		}
		
    }
	
    public void addResult(QueryResult qr) {
		
		if (DEBUG) System.out.println("addResult called for epoch: " + qr.epochNo());
		
		if (qr.epochNo() <= myEpochsToRun) {
			addResultForEpoch(qr.epochNo(), qr.resultVector());
		}
	
		if (!myQueryCompleted && qr.epochNo() == (myEpochsToRun + EXTRA_EPOCHS_TO_WAIT)) {
			//we are done!
			//System.out.println("####Query completing#####");
			myQueryCompleted = true;
			//stop the query
			myNetwork.abortQuery(myQuery);
			//wake up creator
			synchronized(myCreator) {
				myCreator.notify();
			}
		}
		
		try	{
			Thread.currentThread().sleep(200);
		}
		catch (InterruptedException e) { }
    }
	
	/**
	 * Returns true if the test query completed
	 */
	public boolean queryCompleted() {
		return myQueryCompleted;
	}
	
	/**
	 * Returns results for specified epoch, which is ArrayList<Vector>
	 */
	public List getResult(int epoch) {
		return (List)myResults.get(epoch-1);
	}
	
	/**
	 * Returns results for all epochs
	 */
	public List getResults() { return myResults; }
	
	private void addResultForEpoch(int epoch, List result) {
		getResult(epoch).add(result);
	}
	
	private TinyDBNetwork myNetwork;
    private TinyDBQuery myQuery;
	private Object myCreator;
	private short myEpochsToRun;
	private ArrayList myResults;//ArrayList<ArrayList<Vector>>,
	//where myResults[i] is the list of results for epoch i and INDEXING IS 1-based
	private boolean myQueryCompleted = false;
	
	private static final boolean DEBUG = false;
}
