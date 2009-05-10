// $Id: ResultFrame.java,v 1.18 2003/10/30 23:28:35 smadden Exp $

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

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.table.*;
import net.tinyos.message.*;
import net.tinyos.tinydb.awtextra.*;

/** ResultFrame displays a scrolling list with
 results from queries in it, side-by-side with a graph
 of query results when such results are available.
 */
public class ResultFrame extends JFrame implements ResultListener{
	
	
    /** Constructor
	 @param query The query this frame represents (used to determine column headings, result format)
	 @param nw The TinyDBNetwork object used to retransmit & cancel queries
	 */
    public ResultFrame(TinyDBQuery query, TinyDBNetwork nw) {
		this.query = query;
		this.nw = nw;
		
		initUI();
		nw.addResultListener(this, true, query.getId());
		//	addKeyListener(nw);
    }
	
    public ResultFrame() { //for subclasses
		
    }
	
    private void setupGraph(ResultGraph graph) {
	QueryField f = Catalog.curCatalog.getAttr(plotChoices.elementAt(curPlotChoice).toString());
	int min = 0, max = 1000;

	if (f != null) {
	    min = (int)f.getMinVal();
	    max = (int)f.getMaxVal();
	}
	graph.setYRange(min,max);
	graph.setXLabel("Time (s)");
	graph.setYLabel(plotChoices.elementAt(curPlotChoice).toString() + "(Raw Units)");
	graph.setTitle("Time vs. " + plotChoices.elementAt(curPlotChoice).toString());
	graph.setTitleFont("helvetica-bold-24");
	graph.setLabelFont("serif-18");
    }
	
    /* Create the UI */
    private void initUI() {
	    Vector headings = query.getColumnHeadings();
		
	    setTitle ("Query " + query.getId());
		
	    getContentPane().setLayout(new BorderLayout());
	    getContentPane().setBackground(java.awt.Color.white);
		
		
	    addWindowListener(new WindowAdapter() {
					public void windowClosing(WindowEvent evt) {
						exitForm(evt);
					}
				});
		
	    // determine if we should display a graph
	    // graph appears if:
	    // 1) nodeid is available as an attribute or
	    // 2) query is grouped
	    boolean shouldGraph = query.isAgg()?true:false;
	    //	if (headings.size() == 3) {
		
	    for (int i = 1; i < headings.size(); i++) {
			String h = (String)headings.elementAt(i);
			
			System.out.println("headings = " + headings);
			System.out.println("h = " + h);
			System.out.println("query = " + query);
			
			
			if ((h.equals("nodeid") && query.numFields() > 1) || query.grouped() && h.equals(query.groupColName())) {
				nodeIdCol = i;
				shouldGraph = true;
			} else {
				if (query.getFieldType(i) != QueryField.STRING || query.getFieldType(i) != QueryField.BYTES) {
					PlotChoice pc = new PlotChoice();
					
					pc.idx = i;
					pc.name = (String)headings.elementAt(i);
					plotCol = i;
					curPlotChoice = plotChoices.size();
					plotChoices.addElement(pc);
				}
			}
	    }
	    if (plotChoices.size() == 0 || query.hasOutputAction()) 
			shouldGraph = false; //if there's nothing to plot, we shouldn't graph!
	   
	    //	}
		
	    graphing = shouldGraph;
		
	    tableModel = new DefaultTableModel(headings, 0);
	    resultTable = new JTable(tableModel);
	    if (query.hasOutputAction())
		resultTable.setSize(0,0);
	    else
		resultTable.setSize(200,150);
	    resultTable.setFont(Font.decode("serif-16"));
	    resultTable.getTableHeader().setFont(Font.decode("helvetica-bold-18"));
	    scroller = new JScrollPane(resultTable);
		
	    if (shouldGraph) {
			graphPanel = new JPanel();
			graphPanel.setLayout(new BorderLayout());
			
			graphControlPanel = new JPanel(new GridLayout(1,3));
			resetButton = new JButton("Reset Graph");
			resetButton.addActionListener( new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							graph.clear(true);
							setupGraph(graph);
							nodeids = new Hashtable();
							
						}
					});
			
			clearButton = new JButton("Clear Graph");
			clearButton.addActionListener( new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							graph.clear(false);
							graph.setYRange(0d,400d);
							//nodeids = new Hashtable();
						}
					});
			
			
			graphOptions = new JComboBox();
			graphOptions.setLightWeightPopupEnabled(false);
			graph = new ResultGraph(2);
			setupGraph(graph);
			
			for (int i = 0; i < plotChoices.size(); i++) {
				graphOptions.addItem(plotChoices.elementAt(i));
			}
			
			graphOptions.setSelectedIndex(curPlotChoice);
			
			
			
			graphControlPanel.add(graphOptions);
			
			graphOptions.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							PlotChoice pc = (PlotChoice)graphOptions.getSelectedItem();
							if (pc.idx != plotCol) {
								plotCol = pc.idx;
								curPlotChoice = graphOptions.getSelectedIndex();
								graph.clear(true);
								setupGraph(graph);
								nodeids = new Hashtable();
							}
						}
					});
			graphOptions.setSize(100,100);
			
			graphControlPanel.add(resetButton);
			graphControlPanel.add(clearButton);
			
			
			graphPanel.add(graphControlPanel, "South");
			graphPanel.add(graph, "Center");
			
			split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true);
			getContentPane().add(split, "Center");
			
			split.setTopComponent(scroller);
			split.setBottomComponent(graphPanel);
			split.setDividerLocation(350);
			
	    } else {
		if (!query.hasOutputAction()) getContentPane().add(scroller, "Center");
	    }
		
		
		
	    bottomPanel = new JPanel(new AbsoluteLayout());
	    if (query.getBufferCreateTable()) {
		stopQueryButton = new JButton("Delete Buffer");
	    } else {
		stopQueryButton = new JButton("Stop Query");
            }
	    //stop the query from running
	    stopQueryButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						aborted = false; //do this everytime
						abortQuery();
					}
				});
	    bottomPanel.add(stopQueryButton, new AbsoluteConstraints(0,0,250,32));
		
	    //retransmit the query
	    resendQueryButton = new JButton("Resend Query");
	    resendQueryButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						try {
							nw.sendQuery(query);
						} catch (java.io.IOException e) {
							e.printStackTrace();
						}
					}
				});
	    bottomPanel.add(resendQueryButton, new AbsoluteConstraints(250,0,250,32));
		
	    setLifetimeButton = new JButton("Set Lifetime");
	    setLifetimeButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						Object[] possibleValues = { new Integer(24), new Integer(24*7), new Integer(24*7*4), new Integer(24*7*8), new Integer(24*7*12) };
						Object selectedValue = JOptionPane.showInputDialog(null,
																		   "Select query lifetime (hours):", "Hours:",
																		   JOptionPane.INFORMATION_MESSAGE, null,
																		   possibleValues, null);
						if (selectedValue != null) {
							fasterButton.setEnabled(false);
							slowerButton.setEnabled(false);
							curRateLabel.setText(selectedValue + " hours");
							
							Message lifetimeMsg = CommandMsgs.setLifetimeCmd(CmdFrame.BCAST_ADDR,
																				 (byte)query.getId(),
																				 ((Integer)selectedValue).shortValue());
							nw.sendMessage(lifetimeMsg,1);
						}
						
					}
				});
		
	    bottomPanel.add(setLifetimeButton, new AbsoluteConstraints(510, 0,150,32));
		
	    if (query.getEpoch() != TinyDBQuery.kEPOCH_DUR_ONE_SHOT) {
			ratePanel = new JPanel(new AbsoluteLayout());
			curRateLabel = new JLabel(new Integer(query.getEpoch()).toString() + "ms/sample");
			
			fasterButton = new JButton(new ImageIcon("images/up.gif"));
			fasterButton.setSize(60,30);
			fasterButton.addActionListener( new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							int rate = query.getEpoch();
							rate += Math.max(32,((rate / 4)/32)*32);
							if (rate < 0) rate = 32736;
							nw.sendMessage(query.setRateMessage(rate),1);
							curRateLabel.setText(new Integer(query.getEpoch()).toString() + "ms/sample");
							if (graph != null) graph.clear(true);
						}
					});
			
			slowerButton = new JButton(new ImageIcon("images/down.gif"));
			slowerButton.setSize(60,30);
			slowerButton.addActionListener( new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							int rate = query.getEpoch();
							rate -= Math.max(32,((rate / 4)/32)*32);
							if (rate >= 64) {
								nw.sendMessage(query.setRateMessage((short)rate),1);
								curRateLabel.setText(new Integer(query.getEpoch()).toString() + "ms/sample");
								if (graph != null) graph.clear(true);
							}
						}
					});
			
			ratePanel.add(curRateLabel, new AbsoluteConstraints(0,0,150,32));
			ratePanel.add(slowerButton, new AbsoluteConstraints(155,0,32,32));
			ratePanel.add(fasterButton, new AbsoluteConstraints(187,0,32,32));
			
			
			bottomPanel.add(ratePanel, new AbsoluteConstraints(660,0,230,32));
	    }
	    getContentPane().add(bottomPanel, "South");
		
	    JTextArea sqlString = new JTextArea(query.getSQL());
	    sqlString.setFont(Font.decode("serif-16"));
	    sqlString.setLineWrap(true);
	    sqlString.setEditable(false);
	    getContentPane().add(sqlString,"North");
		
		
	    pack();
		
    }
	
    /** ResultListener method called when a new result for
	 this frame's query arrives
	 */
    public void addResult(QueryResult qr) {
	    Vector resultVector = qr.resultVector();
		
	    if (resultVector == null || resultVector.size() <= 1) return;
		
	    if (qr.epochNo() > epochNo)
			epochNo = qr.epochNo(); //monotonically increasing
		
	    tableModel.addRow(qr.resultVector());
	    resultTable.setRowSelectionInterval(tableModel.getRowCount()-1,tableModel.getRowCount()-1);
		
		
	    JScrollBar bar = scroller.getVerticalScrollBar();
	    if (bar != null) {
			bar.setValue(bar.getMaximum() + 128);
	    }

			
	    try { //add the label for the result to the graph key
		
		//update the graph with the new result (if we are graphing)
		//don't draw lines that go backwards!
		Integer nodeid;
		if (nodeIdCol != -1)
		    nodeid = new Integer((String)resultVector.elementAt(nodeIdCol));
		else
		    nodeid = new Integer(0);
		Integer last = (Integer)lastEpoch.get(nodeid);
		if (graphing && (last == null || qr.epochNo() >= last.intValue())) {
		    
		    lastEpoch.put(nodeid, new Integer(qr.epochNo()));
		    Integer idx = null;
		    if (nodeIdCol != -1) {
			String nodeIdStr = (String)resultVector.elementAt(nodeIdCol);
					idx = (Integer)nodeids.get(nodeIdStr);
					if (idx == null) {
					    idx = new Integer(nextId);
					    graph.addKey(nextId++, nodeIdStr);
					    nodeids.put(nodeIdStr, idx);
					}
					
		    }
		    
		    
		    String str = (String)resultVector.elementAt(plotCol);
		    
		    if (str != null) { //if this result has a sensor id appended to it, strip it away
			if (str.indexOf("(") != -1) {
			    str = str.substring(0, str.indexOf("(")).trim();
			}
			try {
			    graph.addPoint(idx == null?0:idx.intValue(), (double)qr.epochNo() * ((double)query.getEpoch() / 1000.0), new Integer(str).intValue());
			} catch (NumberFormatException e) {
			    e.printStackTrace();
			}
		    }
		       
		}
	    } catch (ArrayIndexOutOfBoundsException e) {
		if (TinyDBMain.debug) System.out.println("Result missing value: " + qr);
	    } catch (NumberFormatException e) {
		if (TinyDBMain.debug) System.out.println("Bad result: " + qr);
	    }
		
    }
	
    public void paint(Graphics g) {
	    super.paint(g);
    }
	
    protected void exitForm(WindowEvent evt) {
	    isRunning = false;
	    //only delete query on exit if it is not for a buffer
	    if (!query.getBufferCreateTable()) abortQuery();
	    TinyDBMain.notifyRemovedQuery(query);
    }
	
    //Cancel the currently running query
    private void abortQuery() {
	    if (!aborted) {
			try {
				isRunning = false;
				aborted = true;
				nw.abortQuery(query);
			} catch (Exception e) {
				e.printStackTrace();
			}
	    }
    }
	
	
    public int getEpoch() {
	    return epochNo;
    }
	
    JTable resultTable;
    DefaultTableModel tableModel;
    JPanel bottomPanel;
    JPanel graphPanel;
    JPanel graphControlPanel;
    JButton stopQueryButton;
    JButton resendQueryButton;
    JButton setLifetimeButton;
    JScrollPane scroller;
    ResultGraph graph = null;
    JComboBox graphOptions;
    JButton resetButton;
    JButton clearButton;
    JPanel ratePanel;
    JButton fasterButton;
    JButton slowerButton;
    JLabel curRateLabel;
	
    protected TinyDBQuery query;
    TinyDBNetwork nw;
	
    boolean aborted = false;
	
    JSplitPane split;
	boolean graphing = false;
    int nodeIdCol = -1;
    Hashtable nodeids = new Hashtable();
    Hashtable lastEpoch = new Hashtable();
	int plotCol;
	int curPlotChoice;
	Vector plotChoices = new Vector();
    int nextId = 0;
	
    boolean isRunning = true;
    
    int epochNo = 0;
	
    static final byte QUERY_MSG_ID = 101;
}

class PlotChoice {
	String name;
	int idx;
	
    public String toString() {
		return name;
    }
}
