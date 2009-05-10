// $Id: TinyDBStatus.java,v 1.5 2003/10/07 21:46:07 idgay Exp $

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
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import net.tinyos.message.*;

public class TinyDBStatus extends JFrame implements MessageListener {
    public TinyDBStatus(TinyDBNetwork nw, MoteIF mif, boolean showWindow) {
	this.nw = nw;
	this.mif = mif;
	mif.registerListener(new StatusMsg(), this);
	
	this.showWindow = showWindow;

	if (showWindow) {
	    setSize(225,300);
	    getContentPane().setLayout(new BorderLayout());
	    
	    queryList = new JList();
	    queryList.setSize(200,200);
	    scroller = new JScrollPane(queryList);
	    scroller.setSize(200,200);
	    
	    getContentPane().add(scroller,"Center");
	    getContentPane().add(refreshButton, "South");
	    getContentPane().add(titleLabel, "North");
	    refreshButton.addActionListener ( new ActionListener() {
		    public void actionPerformed(ActionEvent evt) {
			requestStatus(1000,1);
		    }
		});
	    this.show();
	}
    }

    /** Send a status request message up to retries times, or until 
	a reponse is received, waiting timeOutMs
	milliseconds between each attempt 
	(or not at all if timeOutMs <= 0)
	@param timeOutMs If > 0, wait this after and between sending requests
	@param retries Number of times to resend the status request (if it is not heard)
	               If <= 1, will send request once
    */
    static final int MS_PER_SLEEP = 50;

    public void requestStatus(int timeOutMs, int retries) {
	StatusMsg smsg = new StatusMsg();
	smsg.set_fromBase((byte)1);
	heardResponse = false;
	if (retries <= 0) retries = 1;
	while (!heardResponse && retries-- > 0) {
	    nw.sendMessage((Message)smsg, 1);
	    try {
		while (timeOutMs > 0 && !heardResponse) {
		    Thread.currentThread().sleep(MS_PER_SLEEP);
		    timeOutMs -= MS_PER_SLEEP;
		}
	    } catch (InterruptedException e) {
	    }

	}

    }

    public void messageReceived(int addr, Message m) {
	if (m instanceof StatusMsg) {
	    StatusMsg smsg = (StatusMsg)m;
	    heardResponse = true;

	    queries = new Vector();
	    for (int i = 0; i < smsg.get_numQueries(); i++) {
		queries.addElement(new Integer(smsg.getElement_queries(i)));
		System.out.println("Got query id : " + smsg.getElement_queries(i));
	    }

	    if (showWindow) queryList.setListData(queries);
	}
    }

  public int getMaxQid() {
    int max = -1;
    for (int i = 0; i < queries.size(); i++) {
      Integer qid = (Integer)queries.elementAt(i);
      if (qid.intValue() > max)
	max = qid.intValue();
    }
    return max;
  }

  public Vector getQueryIds() {
	  return queries;
  };

    Vector queries = new Vector();
    TinyDBNetwork nw;
    MoteIF mif;
    boolean showWindow;
    boolean heardResponse;

    JButton refreshButton = new JButton("Refresh");
    JLabel loadingLabel = new JLabel(new ImageIcon("images/loading.gif"));
    JLabel emptyLabel = new JLabel("");
    JScrollPane scroller;
    JList queryList;
    JLabel titleLabel = new JLabel("Running Queries");
}
