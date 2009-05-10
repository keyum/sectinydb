// $Id: TextPanel.java,v 1.10 2003/10/07 21:46:07 idgay Exp $

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
/*
 * TextQueryFrame.java
 * Main class to allow users to distribute queries over the network...
 * Created on July 12, 2002, 12:49 PM
 */

/**
 *
 * @author  kyle
 * Edited April 2003 to add savedQueries functionality. Eugene
 */

package net.tinyos.tinydb;

import javax.swing.*;
import java.util.*;
import javax.swing.border.*;
import javax.swing.event.*;
import java.io.*;
import java.sql.*;

import net.tinyos.tinydb.awtextra.*;
//import net.tinyos.tinydb.topology.*;

import net.tinyos.tinydb.parser.*;

public class TextPanel extends JPanel  {
	
    /** Creates new form QueryFrame */
    public TextPanel(TinyDBNetwork nw) {
		this.nw = nw;
		if (Config.getParam("enable-logging").equalsIgnoreCase("true"))
			loggingOn = true;
		else
			loggingOn = false;
		
		mySavedQueries = new Vector(Catalog.currentCatalog().getPredefinedQueries());
		//init ui
		initComponents();
    }
	
    //construct the UI
    private void initComponents() {
		
		sqlString = new JTextArea();
		sqlString.setLineWrap(true);
		sqlString.setEditable(true);
		sqlString.setBorder(new LineBorder(new java.awt.Color(0, 0, 0)));
		if (Config.getParam("default-query") != null)
			sqlString.setText(Config.getParam("default-query"));
		
		errorMessage = new JTextArea();
		errorMessage.setEditable(false);
		errorMessage.setLineWrap(true);
		errorMessage.setBorder(null);
		
		lstSavedQueries = new JList();
		lstSavedQueries.setListData(mySavedQueries);
		lstSavedQueries.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		lstSavedQueries.setBorder(new LineBorder(new java.awt.Color(0, 0, 0)));
		
		lstSavedQueries.addListSelectionListener(new ListSelectionListener() {
					public void valueChanged(ListSelectionEvent e) {
						sqlString.setText((String)lstSavedQueries.getSelectedValue());
					}
				});
		
		savedQueriesScrollPane = new JScrollPane(lstSavedQueries);
		
		typeQueryLabel = new JLabel("Enter SQL Query:");
		errorMessageLabel = new JLabel("Error Messages:");
		savedQueriesLabel = new JLabel("Or select a predefined query:");
		
		setLayout(new AbsoluteLayout());
		add(errorMessageLabel, new AbsoluteConstraints(410, 50, -1, -1));
		add(errorMessage, new AbsoluteConstraints(410, 80, 150, 50));
		
		add(typeQueryLabel, new AbsoluteConstraints(0,0,-1,-1));
		add(sqlString, new AbsoluteConstraints(0, 30, 400, 200));
		
		add(savedQueriesLabel, new AbsoluteConstraints(0, 250, -1, -1));
		add(savedQueriesScrollPane, new AbsoluteConstraints(0, 280, 400, 100));
    }
	
    public void sendQuery() {
		byte qid = MainFrame.allocateQID();
		
		TinyDBQuery currentQuery = generateQuery(qid, epochDur);
		
		if (currentQuery == null)
			return;
		
		setError("No errors");
		
		//copy this query to savedQueries list
		// but avoid making duplicate of the previous query
		String currentQueryStr = sqlString.getText();
		String previousQuery = (String)mySavedQueries.get(0);
		if (!currentQueryStr.equals(previousQuery)) {
			mySavedQueries.add(0,sqlString.getText());
			lstSavedQueries.setListData(mySavedQueries);
		}
		
		currentQuery.setSQL(currentQueryStr);
		System.out.println(currentQuery);
		
		ResultFrame rf = new ResultFrame(currentQuery, nw);
		if (loggingOn)
		{
			try {
				DBLogger dbLogger = new DBLogger(currentQuery, sqlString.getText(), nw);
				// XXX keep track of this so we can delete the listener when the query is cancelled
				TinyDBMain.addQueryListener(dbLogger);
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		TinyDBMain.notifyAddedQuery(currentQuery);
		rf.show();
		if (resultWins.size() <= (qid + 1))
			resultWins.setSize(qid+1);
		resultWins.setElementAt(rf,qid);
		try {
			nw.sendQuery(currentQuery);
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
	
	
	
	public void setError(String txt) {
		errorMessage.setText(txt);
		setError = true;
	}
	
    /** Generate a TinyDBQuery to represent the SQL query
	 */
	TinyDBQuery generateQuery(byte queryId, int epochDur) {
		System.out.println("Running query:  " + sqlString.getText());
		System.out.println("Query ID = " + queryId);
		
		setError("");
		
		TinyDBQuery tdb_query = null;
		
		try {
			tdb_query = SensorQueryer.translateQuery(sqlString.getText(), queryId);
		} catch (ParseException pe) {
			setError(pe.getParseError());
			return null;
		}
		
		//    if (tdb_query == null)
		//	setError("Bad query syntax");
		
		return (tdb_query);
	}
	
	
	
    private JTextArea sqlString;
    private JTextArea errorMessage;
	private JList     lstSavedQueries;
	private JScrollPane savedQueriesScrollPane;
	
    private JLabel typeQueryLabel;
    private JLabel errorMessageLabel;
	private JLabel savedQueriesLabel;
    
	private Vector    mySavedQueries;
	
	boolean loggingOn = false;
    boolean setError = false;
    int epochDur = 2048;
    boolean sendingQuery = false;
    TinyDBNetwork nw;
    Vector resultWins = new Vector();
}

