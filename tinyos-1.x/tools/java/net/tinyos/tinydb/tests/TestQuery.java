// $Id: TestQuery.java,v 1.5 2003/10/07 21:46:08 idgay Exp $

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
 * This class encapsulates info about an test query as read from a test file.
 * It also provides convenience functions for parsing, shielding users
 * from details of TinyDB query generation process
 *
 * @author Eugene Shvets
 */

package net.tinyos.tinydb.tests;

import java.util.*;
import net.tinyos.tinydb.*;
import net.tinyos.tinydb.parser.*;

public class TestQuery {
	
	public TestQuery(String query, boolean parsable, short epochsToRun, int waitingTime, ArrayList results) {
		myQuery = query;
		myParsable = parsable;
		myEpochsToRun = epochsToRun;
		myWaitingTime = waitingTime;
		
		myFields = new HashSet();
		
		if (results != null) {
			myResults = (ArrayList)results.clone();
		}
		
	}
	
	/**
	 * Convenience for creating unparsable TestQueries
	 */
	public static TestQuery makeUnparsableQuery(String query) {
		return new TestQuery(query, false, (short)0, 0, null);
	}
	
	public void setFieldList(String fields) {
		if (fields != null) {
			StringTokenizer st = new StringTokenizer(fields, ",");
			while(st.hasMoreTokens()) {
				myFields.add(st.nextToken().trim());
			}
		}
	}
	
	/**
	 * Generates a valid query id for a new query
	 */
	public static byte allocateQueryID() {
		return ourQueryID++;
	}
	
	/**
	 * Generates TinyDBQuery from this TestQuery, by parsing its query string
	 * and setting appropriate number of epochs to run
	 */
	public TinyDBQuery getTinyDBQuery() throws ParseException {
		TinyDBQuery query = SensorQueryer.translateQuery(myQuery, allocateQueryID());
		query.setNumEpochs(myEpochsToRun);
		
		return query;
	}
	
	/**
	 * Returns true if result list of this query is nonempty,
	 * meaning that test case requested result matching against the
	 * actual results for this query
	 */
	public boolean isResultMatchRequested() {
		return myResults != null;
	}
	
	/**
	 * Matches the expected result specified in the test case
	 * to the actual result of query execution
	 * For each tuple of the expected result, checks if the tuple is present
	 * in the actual result, and if not, returns false
	 * If all tuples are present, returns true
	 *
	 */
	public boolean matchResult(int epoch, List actualResult){
		for(Iterator it=getExpectedResult(epoch).iterator();it.hasNext(); ) {
			if (!actualResult.contains(it.next())) return false;
		}
		return true;
	}
	
	/**
	 * Returns list of result tuples expected by this test query
	 */
	public ArrayList getExpectedResult(int epoch) {
		return (ArrayList)myResults.get(epoch-1);
	}
	
	public String getQueryString() { return myQuery; }
	
	public short getEpochsToRun() { return myEpochsToRun; }
	
	public int getWaitingTime() { return myWaitingTime; }
	
	private static byte ourQueryID=0;
	
	private String myQuery;
	private boolean myParsable;
	private HashSet myFields;
	private short myEpochsToRun;
	private int myWaitingTime;
	private ArrayList myResults;//ArrayList<ArrayList<Vector>>,
	//where myResults[i] is the ArrayList of tuples for epoch i+1,
	//and each tuple is a Vector of attribute values
}

