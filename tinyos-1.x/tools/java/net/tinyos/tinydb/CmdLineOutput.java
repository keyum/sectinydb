// $Id: CmdLineOutput.java,v 1.10 2003/10/07 21:46:07 idgay Exp $

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
import net.tinyos.tinydb.parser.*;
import java.util.*;
import java.sql.*;

/** CmdLineOutput runs queries and displays results on the command line.
    @author Sam Madden (madden@cs.berkeley.edu)
*/
public class CmdLineOutput implements ResultListener {
    /** Constructor -- runs the specified query using the
	provided network interface.
	@param nw A network interface for talking with the basestation / 
	          parsing results.
	@param queryString the query to run.
    */
    public CmdLineOutput(TinyDBNetwork nw, String queryString) {
	if (Config.getParam("enable-logging").equalsIgnoreCase("true"))
		loggingOn = true;
	else
		loggingOn = false;
	try {
	    //parse the query
	    byte qid = MainFrame.allocateQID();
	    TinyDBQuery q = SensorQueryer.translateQuery(queryString, qid);

	    Vector headings = q.getColumnHeadings(); //fetch the names of the fields in the result
	    
	    this.q = q;

		// XXX hack! keep query going so that a tuple with the high enough
		// XXX epoch number will be returned and the program can be terminated
		numEpochs = q.numEpochs;
		q.numEpochs = 0;
		// XXX end of hack

		if (loggingOn)
		{
			try {
				DBLogger dbLogger = new DBLogger(q, queryString, nw);
				// XXX keep track of this so we can delete the listener when the query is cancelled
				TinyDBMain.addQueryListener(dbLogger);
			} catch (SQLException e) {
			e.printStackTrace();
			}
		}
	    TinyDBMain.notifyAddedQuery(q); // add query to list of known queries
	    nw.addResultListener(this, true, qid); // set ourselves up to receives results for query id

	    
	    System.out.print("|");
	    for (int i = 0; i < headings.size(); i++) {
		System.out.print("\t" + headings.elementAt(i) + "\t|");
	    }
	    System.out.println("\n-----------------------------------------------------");

	    nw.sendQuery(q); //inject the query

	    
	} catch (ParseException e) {
	    System.err.println("Invalid query : " + queryString + "(" + e + ")");
	    System.err.println(SensorQueryer.errorMessage);
	} catch (java.io.IOException e) {
	    System.err.println("Network error: " + e);
	}
	
    }

    /** ResultListener method that is called whenever a query result arrives for us
	This method just prints each result out on the command line.
	@param qr A query result that just arrived 
    */
    public void addResult(QueryResult qr) {
	Vector v = qr.resultVector();
	for (int i = 0; i < v.size(); i++) {
	    System.out.print("\t" + v.elementAt(i) + "\t|");
	}
	System.out.println();
	if (numEpochs > 0 && qr.epochNo() >= numEpochs)
	{
		//shut down network then exit
		for (int i = 0; i < 1; i++) 
		{
			try
			{
				TinyDBMain.mif.send((short)-1,CommandMsgs.resetCmd((short)-1));
			}
			catch (java.io.IOException e)
			{
		   		e.printStackTrace();
			}
			try 
			{
				Thread.currentThread().sleep(200);
			} 
			catch (InterruptedException e) 
			{ }
		}
		System.exit(0);
	}
    }

    private TinyDBQuery q;
	private int numEpochs;
	private boolean loggingOn = false;
}
