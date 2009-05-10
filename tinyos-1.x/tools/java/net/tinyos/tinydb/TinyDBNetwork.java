// $Id: TinyDBNetwork.java,v 1.23 2003/10/28 21:47:31 smadden Exp $

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
import java.awt.event.*;
import java.awt.*;
import net.tinyos.message.*;

/** TinyDBNetwork is responsible for getting and
    sending results and queries over the network

    @author madden

*/
public class TinyDBNetwork implements  Runnable, QueryListener, MessageListener /*, KeyEventPostProcessor */ {

    static final short IGNORE_AGE = 5; //results older than this many epochs should be ignored

    public static final byte QUERY_MSG_ID = 101; //message ids used by tinydb
    public static final byte DATA_MSG_ID = 100;
    public static final byte UART_MSG_ID = 1;

    public static final short UART_ADDR = 0x007e;
    public static short ROOT_ADDR = UART_ADDR;
    
    //rate at which data messages are broadcast from the root -- this is now parameterized by the
    //rate of the fastest query
    static int baseBcastInterval = Integer.MAX_VALUE; 
    static final int MIN_EPOCH_DUR = 1200;  //never send faster than this...

    private MoteIF mif;

    private Hashtable qidListeners = new Hashtable();  //qid -> Vector(ResultListener)
    private Hashtable processedListeners = new Hashtable(); //qid -> Vector(ResultListener)
    private Vector listeners = new Vector(); //Vector(ResultListener), receive all results
    

    private boolean sendingQuery = false;
    private boolean promiscuous = false; //deliver all messages (if true), or just those addressed to root (if false)

    Vector knownQids = new Vector(); //list of known query ids
    Vector queries = new Vector(); //list of queries, where queries[i].qid = i;  some elements may be null

    
    
    /** Constructor 
	@param mif The MoteIF used to send / receive messages from the motes 
    */
    public TinyDBNetwork(MoteIF mif) {
	Thread t = new Thread(this);

	this.mif = mif;
	
	mif.registerListener(new QueryResultMsg(), this);
	mif.registerListener(new UartMsg(), this);

	t.start();

    }

    
    /** Add a listener to be notified when a query result for
	the specified query id arrives 
	@param rl The ResultListener to add
	@param aggResults Does the listener want processed (e.g. combined aggregate) results, 
	                  or raw results?
        @param qid The query id this listener is interested in
    */
    public void addResultListener(ResultListener rl, boolean aggResults, int qid) {
	Vector qidV;

	if (!aggResults) {
	    qidV = (Vector)qidListeners.get(new Integer(qid));
	} else {
	    qidV = (Vector)processedListeners.get(new Integer(qid));
	}
	if (qidV == null) {
	    qidV = new Vector();
	    if (!aggResults) {
		qidListeners.put(new Integer(qid), qidV);
	    } else {
		processedListeners.put(new Integer(qid), qidV);
	    }
	}
	if (!qidV.contains(rl))
	    qidV.addElement(rl);


    }

    
    /** Add a listener to be notified when any query result
	arrives 
	@param rl The listener to register
    */
    public void addResultListener(ResultListener rl) {
	listeners.addElement(rl);
    }

    /** Remove a specific result listener 
     @param rl The listener to remove
    */
    public void removeResultListener(ResultListener rl) {
	listeners.remove(rl);
	Enumeration e = qidListeners.elements();
	Vector qidV;

	while (e.hasMoreElements()) {
	    qidV = (Vector)e.nextElement();
	    qidV.remove(rl);
	}

	e = processedListeners.elements();
	while(e.hasMoreElements()) {
	    qidV = (Vector)e.nextElement();
	    qidV.remove(rl);
	}
    }


    Vector lastEpochs = new Vector(); //vector of last epochs for all queries
    Vector lastResults = new Vector(); //vector of HashTables by group id of results for all queries

    /** Process a radio message 
     Assumes results are QueryResults -- parses them, and maintains the following
    data structures:
    - most recent epoch heard for each query
    - most recent (paritially aggregated) result for each query
    
    Notifies ResultListeners for all results every time a value arries
    Notifies ResultListeners for raw results for a pariticular query id every time a result for that query arrives
    Notifies ResultListeners for processed results from the current epoch every time a new epoch begins;  the aggregate
                                  combines results that are from the same epoch and are not obviously bogus (e.g.
				  from a ridiculous epoch number);  each group is reported in a different result message.
				  
                             
    */
    public void messageReceived(int addr, Message m) {
	try {
	  if (m instanceof UartMsg) {
	      if (TinyDBMain.debug) System.out.println ("DEBUG MSG: " + ((UartMsg)m).getString_data());
	      return;
	  }
	  if (TinyDBMain.debug) System.out.println("HEARD SOMETHING, addr = " + addr);
	  int dataOffset =  MultiHopMsg.offset_data(0);
	  // MultiHopMsg mhm = new MultiHopMsg(m, m.baseOffset(), 40);
	  QueryResultMsg qrm = new QueryResultMsg(m, m.baseOffset() + dataOffset);
	  // if (TinyDBMain.debug) System.out.println("MultiHopMsg = " + mhm.toString());
	  // if (TinyDBMain.debug) System.out.println("QueryResultMsg = " + qrm.toString());
	  int qid = QueryResult.queryId(qrm);

	  if (lastResults.size() <= (qid+1)) {
	      lastResults.setSize(qid+1);
	  }
	  if (lastEpochs.size() <= (qid+1)) {
	      lastEpochs.setSize(qid+1);
	  }
	  Hashtable curHt = (Hashtable)lastResults.elementAt(qid);
	  QueryResult curQr;
	  Integer le = (Integer)lastEpochs.elementAt(qid);
	  int lastEpoch = (le == null)?-1:le.intValue();
	  TinyDBQuery q = queries.size() > qid?(TinyDBQuery)queries.elementAt(qid):null;
	  if (q != null) {
	    QueryResult newqr = new QueryResult(q, qrm);
	    Vector listeners;
	    Enumeration e;
	    
	    
	    q.setActive(true); //note that we've seen some results for this query recently
	    
	    if (addr != UART_ADDR && !promiscuous) {
	    	if (TinyDBMain.debug) System.out.print("!");
	    	return; //forget about this message if it's not from the root!
	    }

	    //send this result to listeners for all results
	    e = this.listeners.elements();
	    while (e.hasMoreElements()) {
		((ResultListener)e.nextElement()).addResult(newqr);
	    }

	    //plus listeners for unprocessed results for this query id
	    listeners = (Vector)qidListeners.get(new Integer(newqr.qid()));
	    if (listeners != null) {
		e = listeners.elements();
		while (e.hasMoreElements()) {
		    ((ResultListener)e.nextElement()).addResult(newqr);
		}
	    }
		
	    //if (newqr.epochNo() > lastEpoch + 1000) {
	    //if (TinyDBMain.debug) System.out.println("e");
	    //return; //ignore wacky results!
	    //}

	    if (q.isAgg()) {
	      if (TinyDBMain.debug) System.out.println("Result for query " + QueryResult.queryId(qrm) + ":"+ newqr.toString());
	      if (newqr.epochNo() > lastEpoch || curHt == null) { //onto a new epoch!
		if (curHt != null) {
		  Iterator it = curHt.values().iterator();
		  while (it.hasNext()) {
		    curQr = (QueryResult)it.next();
		    listeners = (Vector)processedListeners.get(new Integer(curQr.qid()));
		    if (listeners != null) {
			e = listeners.elements();
			while (e.hasMoreElements()) {
			    ((ResultListener)e.nextElement()).addResult(curQr);
			}
		    }
		  }
		}
		curHt = new Hashtable();
		curHt.put(new Integer(newqr.group()), newqr);
		lastResults.setElementAt(curHt, qid);
		lastEpochs.setElementAt(new Integer(newqr.epochNo()), qid);
		if (TinyDBMain.debug) System.out.print("+");
	     } else if (newqr.epochNo() >= (lastEpoch - IGNORE_AGE)) { //ignore really old results
		curQr = (QueryResult)curHt.get(new Integer(newqr.group()));
		if (curQr != null)
		  curQr.mergeQueryResult(newqr);
		else 
		  curHt.put(new Integer(newqr.group()), newqr);
		//lastEpochs.setElementAt(new Integer(newqr.epochNo()), qid);
	      } else
		  if (TinyDBMain.debug) System.out.print("$");

	    } else { //not agg
		if (/*newqr.epochNo() >= (lastEpoch - IGNORE_AGE)*/true) { //skip old results
		  if (TinyDBMain.debug) System.out.println(Calendar.getInstance().getTime().toString() + " Result for query " + QueryResult.queryId(qrm) + ":"+ newqr.toString());
		listeners = (Vector)processedListeners.get(new Integer(newqr.qid()));
		if (listeners != null) {
		    e = listeners.elements();
		    while (e.hasMoreElements()) {
			((ResultListener)e.nextElement()).addResult(newqr);
		    }
		}
		lastEpochs.setElementAt(new Integer(newqr.epochNo()), qid);
		if (TinyDBMain.debug) System.out.print("+");
	      } else
		  if (TinyDBMain.debug)System.out.print("[$"+newqr.epochNo()+"]");
	    }    


	  } else {
	      if (TinyDBMain.debug) System.out.println("Result for unknown query id : " + qid);
	  }
	} catch (ArrayIndexOutOfBoundsException e) {
	    e.printStackTrace();
	    System.out.print("-");
	}
    }

    /** @return the last epoch for the specified query id
	@throws NoSuchElementException if nothing is known about qid
    */
    public int getLastEpoch(int qid) throws NoSuchElementException {
	Integer le = (Integer)lastEpochs.elementAt(qid);
	int lastEpoch = (le == null)?-1:le.intValue();	    
	return lastEpoch;
    }

    /** Set the last known epoch for the specified query id */
    public void setLastEpoch(int qid, int lastEpoch) {
	if (lastEpochs.size() <= qid) lastEpochs.setSize(qid + 1);
  
	lastEpochs.setElementAt(new Integer(lastEpoch),qid);
    }

    /** Background thread used to periodically send information from the root
	down into the network;  current this information includes:
	a message index (so that children can choose root as parent)
	information about the typical number of senders during an epoch (so that children can schedule comm)
	an epoch number (per query).
    */
    public void run() {
	//we no longer send root beacons -- 8/7/03 SRM
    }


    //QueryListener methods
    /** A new query has begun running.  Use this to track the queries that we need to
	send data messages for (see run() above.)
    */
    public void addQuery(TinyDBQuery q) {
	knownQids.addElement(new Integer(q.getId()));
	if (queries.size() < ( q.getId() + 1))
	    queries.setSize(q.getId() + 1);
	queries.setElementAt(q, q.getId());
	/* Set the rate at which we broadcast data packets to be the
	   epoch duration of the fastest query */
	if (q.getEpoch() < baseBcastInterval) 
	    baseBcastInterval = Math.max(q.getEpoch(),MIN_EPOCH_DUR);
    }

    /** A query has stopped running */
    public void removeQuery(TinyDBQuery q) {
	Integer qid = new Integer(q.getId());
	try {
	    knownQids.remove(qid);
	    processedListeners.remove(qid);
	    qidListeners.remove(qid);
	    queries.setElementAt(null,q.getId());
	    //this was the fastest running query?  if so, choose a new epoch duration
	    if (q.getEpoch() == baseBcastInterval) {
		baseBcastInterval = Integer.MAX_VALUE;
		for (int i = 0; i < queries.size(); i++) {
		    TinyDBQuery tmpq = (TinyDBQuery)queries.elementAt(i);
		    if (tmpq != null)
			if (tmpq.getEpoch() < baseBcastInterval)
			    baseBcastInterval = tmpq.getEpoch();
		}
	    }
	} catch (NoSuchElementException e) {
	    System.out.println("Error removing query.");
	} catch (ArrayIndexOutOfBoundsException e) {
	}
    }



    /** Send the specified query out over the radio */
    public void sendQuery(TinyDBQuery q) throws java.io.IOException{
	sendingQuery = true;
	Iterator it = q.messageIterator(); //generate messages for this query

	try {
	    if (TinyDBMain.debug) System.out.println("Sending query.");
	    while (it.hasNext()) {
		Message msg = (Message)it.next();

		mif.send(MoteIF.TOS_BCAST_ADDR,msg);
		try {
		    Thread.currentThread().sleep(1000);
		} catch (InterruptedException e) {
		}
	    }
	} catch (java.io.IOException e) {

	    throw e;
	}
	sendingQuery = false;
    }

    public boolean sendingQuery() {
	return sendingQuery;
    }

    /** Send message to abort the specified query out over the radio */
    public void abortQuery(TinyDBQuery query)
    {

	for (int i = 0; i < 5; i++)
	    {
		try
		    {
			mif.send(MoteIF.TOS_BCAST_ADDR,query.abortMessage());
			Thread.currentThread().sleep(200);
		    }
		catch (Exception e)
		    {
			e.printStackTrace();
		    }
	    }
	//HACK -- use this as a hint to start heartbeating about another query!
	query.setActive(false);
    }

    
    /** Send the specified message retries times */
    public void sendMessage(Message m, int retries) {
	for (int i = 0; i < retries; i++)
	    {
		try
		    {
			mif.send(MoteIF.TOS_BCAST_ADDR,m);
			Thread.currentThread().sleep(200);
		    }
		catch (Exception e)
		    {
			e.printStackTrace();
		    }
	    }
    }

    /** Return baseBcastInterval, which controls how often data messages are 
	sent out from the base station so that nodes can see
	the root.
    */	
    public static int getBaseBcastInterval()
    {
  	return baseBcastInterval;
    }

    /** Set the base station data message broadcast interval */
    public static void setBaseBcastInterval(int interval)
    {
	baseBcastInterval = interval;
    }

	public static void setHeader(NetworkMsg m)
	{
		m.set_hdr_idx((short)0);
		m.set_hdr_senderid(TinyDBNetwork.UART_ADDR);
		m.set_hdr_parentid(ROOT_ADDR);
		m.set_hdr_level((short)0);
		m.set_hdr_timeRemaining((byte)255);
	}

    public void setPromiscuous(boolean promiscuous) {
	this.promiscuous = promiscuous;
    }
    

    static final short BCAST_ADDR = (short)-1;

}
