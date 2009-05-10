// $Id: GuiPanel.java,v 1.11 2003/10/07 21:46:07 idgay Exp $

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
 * QueryFrame.java
 * Main class to allow users to build and distribute queries over the network...
 * Created on May 21, 2002, 10:16 AM
 */

/**
 *
 * @author  madden
 */

package net.tinyos.tinydb;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.border.*;
import java.io.*;
import java.sql.*;

import net.tinyos.tinydb.awtextra.*;
import net.tinyos.tinydb.topology.*;

import net.tinyos.tinydb.parser.*;

public class GuiPanel extends JPanel implements CatalogListener {
    //constants for UI layout
    static final int PANEL_WID = 530; //width of main panel (excluding buttons on right side)
    static final int BUT_SEP = 10; //separator between buttons
    static final int SEND_BUT_TOP = 5;
    static final int BUT_HEIGHT = 30; //height of buttons
    static final int CHECK_BOX_LEFT = 10;
    static final int CHECK_BOX_WID = 20; //width of check box without labels
    static final int ATTR_POPUP_WID = 120; //width of an attribute popup
    static final int GROUP_LABEL_WID = 100; //width of "group by" label
    static final int GRP_OPS_WID = 60;  //width of group by operations combo box
    static final int GRP_CONST_WID = 60;  //width of group by constant field box
    static final int SELECT_PANEL_HEIGHT = 105;     //height of select panel
    static final int SCROLLER_LABEL_WID = 200;	 //width of labels at top of scroller panels
    static final int SCROLLER_HEIGHT = 150; //height of scroller box
    static final int SCROLLER_TOP = 60; //top of scroller box
    static final int L_SCROLLER_LEFT = 20; //left side of scroller box
    static final int EPOCH_LABEL_WID = 150; //width of "epoch duration" label
    static final int TOP_ROW = 5; //where the top row begins
    static final int TEXT_HEIGHT = 20; //height of text items
    static final int SQL_BOX_HEIGHT = 90; //height of SQL string text box
    static final int TRIGGER_LABEL_WID = 150; //width of "trigger action" label
    static final int TRIGGER_ACTION_WID = 190; //width of trigger action popup
    static final int LOG_CHECK_WID = 200;
    
    static final int SEND_BUT_LEFT = PANEL_WID + BUT_SEP;
    static final int TOPO_BUT_TOP = SEND_BUT_TOP + BUT_HEIGHT + BUT_SEP;
    static final int MAGNET_BUT_TOP = TOPO_BUT_TOP + BUT_HEIGHT + BUT_SEP;
    static final int GROUP_LABEL_LEFT = CHECK_BOX_LEFT + CHECK_BOX_WID;
    static final int ATTR_POPUP_LEFT = GROUP_LABEL_LEFT + GROUP_LABEL_WID;
    static final int GRP_OPS_LEFT = ATTR_POPUP_LEFT + ATTR_POPUP_WID;
    static final int GRP_CONST_LEFT = GRP_OPS_LEFT + GRP_OPS_WID;
    static final int NEW_PRED_LEFT = GRP_CONST_LEFT + GRP_CONST_WID + BUT_SEP - 5;  //the side of the button was being cut off, thus -5
    static final int GROUP_PANEL_HEIGHT = BUT_HEIGHT;
    static final int SCROLLER_WIDTH = SCROLLER_LABEL_WID - 20;
    static final int AGG_BOX_LEFT = L_SCROLLER_LEFT + SCROLLER_WIDTH + BUT_SEP;
    static final int SEL_BUTTON_LEFT = AGG_BOX_LEFT + 20;
    static final int AGG_BOX_WID = ATTR_POPUP_WID;
    static final int R_SCROLLER_LEFT = AGG_BOX_LEFT + AGG_BOX_WID + BUT_SEP;
    static final int ATTR_BUT_TOP = SCROLLER_TOP + BUT_HEIGHT; //top of scroller attribute button
    static final int SEL_BUT_TOP = ATTR_BUT_TOP + BUT_HEIGHT + 5;
    static final int EPOCH_BOX_WID = ATTR_POPUP_WID;
    static final int EPOCH_BOX_LEFT = L_SCROLLER_LEFT + EPOCH_LABEL_WID;
    
    static final int SCROLLER_LABEL_TOP = SCROLLER_TOP - TEXT_HEIGHT;
    static final int SQL_BOX_LEFT = L_SCROLLER_LEFT;
    static final int SQL_BOX_TOP = SCROLLER_TOP + SCROLLER_HEIGHT + BUT_SEP;
    static final int SQL_BOX_WID = (R_SCROLLER_LEFT - L_SCROLLER_LEFT) + SCROLLER_WIDTH;
    static final int GROUP_PANEL_TOP = SQL_BOX_TOP + SQL_BOX_HEIGHT + BUT_SEP; //was 310
    static final int SELECT_PANEL_TOP = GROUP_PANEL_TOP + GROUP_PANEL_HEIGHT+ BUT_SEP;
	
    static final int TRIGGER_TOP = SELECT_PANEL_TOP + SELECT_PANEL_HEIGHT + BUT_SEP;
    static final int TRIGGER_LABEL_LEFT = GROUP_LABEL_LEFT;
    static final int TRIGGER_ACTION_LEFT = TRIGGER_LABEL_LEFT + TRIGGER_LABEL_WID + BUT_SEP;
    static final int LOG_CHECK_LEFT = TRIGGER_ACTION_LEFT + TRIGGER_ACTION_WID + BUT_SEP;
    static final int TRIGGER_PANEL_WID = LOG_CHECK_LEFT + LOG_CHECK_WID;
    
    /** Creates new panel GuiPanel */
    public GuiPanel(TinyDBNetwork nw) {
		//init ui
		this.nw = nw;
		initComponents();
		Catalog.curCatalog.addListener(this);
    }
    
    //construct the UI
    private void initComponents() {
		UIManager.put("Label.font", normalFont);
		UIManager.put("Button.font", normalFont);
		UIManager.put("CheckBox.font", normalFont);
		UIManager.put("ComboBox.font", normalFont);
		setFont(normalFont);
		setFont(normalFont);
		
		selectGroupPanel = new JPanel();
		selectGroupPanel.setFont(normalFont);
		groupByPanel = new JPanel();
		groupCheckBox = new JCheckBox();
		groupLabel = new JLabel();
		
		groupBox = new JComboBox();
		groupBox.setLightWeightPopupEnabled(false);
		addFieldsToMenu(groupBox);
		
		groupByOps = new JComboBox();
		groupByOps.setLightWeightPopupEnabled(false);
		addArithOpsToMenu(groupByOps);
		groupByOps.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						JComboBox cb = (JComboBox)evt.getSource();
						String op = (String)cb.getSelectedItem();
						if (!op.equals("")) {
							groupByConst.setEnabled(true);
						} else {
							groupByConst.setEnabled(false);
						}
						updateSQL();
						//updateAttributeLists();
					}
				});
		
		groupByConst = new JTextField();
		groupByConst.setEnabled(false);
		groupByConst.getDocument().addDocumentListener(new DocumentListener() {
					public void changedUpdate(DocumentEvent e){
						updateSQL();
					}
					public void insertUpdate(DocumentEvent e){
						updateSQL();
					}
					public void removeUpdate(DocumentEvent e){
						updateSQL();
					}
				});
		groupByConst.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						//updateAttributeLists();
					}
				});
		
		attenuationBox = new JComboBox(attens);
		attenuationBox.setLightWeightPopupEnabled(false);
		aggregateBox = new JComboBox();
		aggregateBox.setLightWeightPopupEnabled(false);
		addAggsToMenu(aggregateBox);
		epochBox = new JComboBox();
		epochBox.setLightWeightPopupEnabled(false);
		addEpochsToMenu(epochBox);
		newPredButton = new JButton();
		selectSrcList = new JList();
		selectSrcList.setFont(textBoxFont);
		selectDestList = new JList();
		selectDestList.setFont(textBoxFont);
		removeSelButton = new JButton();
		addSelButton = new JButton();
		selectFieldsLabel = new JLabel();
		selectedLabel = new JLabel();
		sqlString = new JTextArea();
		sqlString.setLineWrap(true);
		sqlString.setEditable(false);
		sqlString.setBorder(new LineBorder(new java.awt.Color(0, 0, 0)));
		sqlString.setFont(textBoxFont);
		
		triggerCheckBox = new JCheckBox();
		triggerLabel = new JLabel("TRIGGER ACTION");
		triggerActionBox = new JComboBox(triggerActions);
		triggerActionBox.setLightWeightPopupEnabled(false);
		triggerPanel = new JPanel();
		
		logCheckBox = new JCheckBox("Log to Database");
		logCheckBox.setSelected(false);
		
		jSeparator2 = new JSeparator();
		
		setLayout(new AbsoluteLayout());
		final GuiPanel queryFrame = this;
		
		selectGroupPanel.setLayout(new java.awt.GridLayout(3, 0, 5, 5));
		//        selectGroupPanel.setBackground(java.awt.Color.white);
		selectGroupPanel.setBorder(new BevelBorder(BevelBorder.LOWERED));
		
		groupByPanel.setLayout(new AbsoluteLayout());
		
		//        groupByPanel.setBackground(java.awt.Color.white);
		
		groupBox.setEnabled(false);
		oldGroup = groupBox.getSelectedItem();
		groupBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						if (oldGroup != groupBox.getSelectedItem()) {
							if (!checkSelectionConsistency(selectDestList,null)) {
								groupBox.setSelectedItem(oldGroup);
							} else {
								oldGroup = groupBox.getSelectedItem();
								constrainAggregateChoices();
							}
						}
					}
				});
		
		groupLabel.setEnabled(false);
		groupByOps.setEnabled(false);
		groupByConst.setEnabled(false);
		
		//        groupCheckBox.setBackground(java.awt.Color.white);
		
		
		groupCheckBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						groupCheckBoxAction(evt);
					}
				});
		
		
		
		groupByPanel.add(groupCheckBox, new AbsoluteConstraints(CHECK_BOX_LEFT, 0, CHECK_BOX_WID, BUT_HEIGHT));
		
		
		groupLabel.setText("GROUP BY");
		groupByPanel.add(groupLabel, new AbsoluteConstraints(GROUP_LABEL_LEFT, 0, GROUP_LABEL_WID, BUT_HEIGHT));
		groupByPanel.add(groupBox, new AbsoluteConstraints(ATTR_POPUP_LEFT, 0, ATTR_POPUP_WID, BUT_HEIGHT));
		groupByPanel.add(groupByOps, new AbsoluteConstraints(GRP_OPS_LEFT, 0, GRP_OPS_WID, BUT_HEIGHT));
		groupByPanel.add(groupByConst, new AbsoluteConstraints(GRP_CONST_LEFT, 0, GRP_CONST_WID, BUT_HEIGHT));
		
		add(groupByPanel, new AbsoluteConstraints(0,GROUP_PANEL_TOP, PANEL_WID, GROUP_PANEL_HEIGHT));
		
		add(selectGroupPanel, new AbsoluteConstraints(0, SELECT_PANEL_TOP , PANEL_WID, SELECT_PANEL_HEIGHT));
		
		newPredButton.setText("New Predicate");
		newPredButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						newPredButtonActionPerformed(evt);
					}
				});
		
		groupByPanel.add(newPredButton, new AbsoluteConstraints(NEW_PRED_LEFT, 0, -1, BUT_HEIGHT));
		
		///////////////////////////////////
		// List of available attributes
		
		selectSrcList.setBorder(new LineBorder(new java.awt.Color(0, 0, 0)));
		selectSrcList.setMinimumSize(new java.awt.Dimension(100, 100));
		selectSrcList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		addSelectChoices(selectSrcList);
		
		selectSrcList.addMouseListener(new MouseAdapter() {
					public void mouseClicked(MouseEvent evt) {
						constrainAggregateChoices();
						//add to dest list if double click
						if (evt.getClickCount() > 1) {
							addSelButtonActionPerformed();
						}
					}
				});
		
		JScrollPane srcScroller = new JScrollPane(selectSrcList);
		add(srcScroller, new AbsoluteConstraints(L_SCROLLER_LEFT, SCROLLER_TOP,
												 SCROLLER_WIDTH, SCROLLER_HEIGHT));
		
		////////////////////////////////////
		// List of attributes in query
		
		selectDestList.setBorder(new LineBorder(new java.awt.Color(0, 0, 0)));
		selectDestList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		
		selectDestList.addMouseListener(new MouseAdapter() {
					public void mouseClicked(MouseEvent evt) {
						if (evt.getClickCount() > 1) {
							removeSelButtonActionPerformed();
						}
					}
				});
		
		JScrollPane destScroller = new JScrollPane(selectDestList);
		add(destScroller, new AbsoluteConstraints(R_SCROLLER_LEFT, SCROLLER_TOP,
												  SCROLLER_WIDTH,
												  SCROLLER_HEIGHT));
		
		
		
		removeSelButton.setText("<<<");
		removeSelButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						removeSelButtonActionPerformed();
					}
				});
		
		add(aggregateBox, new AbsoluteConstraints(AGG_BOX_LEFT, ATTR_BUT_TOP, AGG_BOX_WID,BUT_HEIGHT));
		
		add(addSelButton, new AbsoluteConstraints(SEL_BUTTON_LEFT, SEL_BUT_TOP, -1, -1));
		
		add(removeSelButton, new AbsoluteConstraints(SEL_BUTTON_LEFT, SEL_BUT_TOP + BUT_HEIGHT, -1, -1));
		
		addSelButton.setText(">>>");
		addSelButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						addSelButtonActionPerformed();
					}
				});
		
		
		
		
		JLabel epochsLabel = new JLabel();
		epochsLabel.setText("Sample Period");
		add(epochsLabel, new AbsoluteConstraints(L_SCROLLER_LEFT, TOP_ROW + 5, -1, TEXT_HEIGHT));
		
		add(epochBox, new AbsoluteConstraints(EPOCH_BOX_LEFT, TOP_ROW ,ATTR_POPUP_WID,BUT_HEIGHT));
		epochBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						epochDur = ((Integer)epochBox.getSelectedItem()).intValue();
						updateSQL();
					}
					
				});
		
		selectFieldsLabel.setText("Available Attributes");
		selectFieldsLabel.setFont(boldFont);
		add(selectFieldsLabel, new AbsoluteConstraints(L_SCROLLER_LEFT, SCROLLER_LABEL_TOP,
													   SCROLLER_LABEL_WID, TEXT_HEIGHT));
		
		selectedLabel.setText("Projected Attributes");
		selectedLabel.setFont(boldFont);
		add(selectedLabel, new AbsoluteConstraints(R_SCROLLER_LEFT, SCROLLER_LABEL_TOP,
												   SCROLLER_LABEL_WID, TEXT_HEIGHT));
		
		add(jSeparator2, new AbsoluteConstraints(-10, 30, 600, 0));
		
		add(sqlString, new AbsoluteConstraints(SQL_BOX_LEFT, SQL_BOX_TOP,
											   SQL_BOX_WID, SQL_BOX_HEIGHT));
		updateSQL();
		
		
		
		triggerPanel.setLayout(new AbsoluteLayout());
		
		triggerActionBox.setEnabled(false);
		triggerActionBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						updateSQL();
					}
				});
		
		triggerLabel.setEnabled(false);
		
		triggerCheckBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						triggerCheckBoxAction();
					}
				});
		triggerPanel.add(triggerCheckBox, new AbsoluteConstraints(CHECK_BOX_LEFT, 0, CHECK_BOX_WID, BUT_HEIGHT));
		triggerPanel.add(triggerLabel, new AbsoluteConstraints(TRIGGER_LABEL_LEFT, 0, TRIGGER_LABEL_WID, BUT_HEIGHT));
		triggerPanel.add(triggerActionBox, new AbsoluteConstraints(TRIGGER_ACTION_LEFT, 0, TRIGGER_ACTION_WID, BUT_HEIGHT));
		triggerPanel.add(logCheckBox, new AbsoluteConstraints(LOG_CHECK_LEFT,0,LOG_CHECK_WID,-1));
		
		add(triggerPanel, new AbsoluteConstraints(0,TRIGGER_TOP, TRIGGER_PANEL_WID, BUT_HEIGHT));
		
		
    }
    
    public void magnetDemo() {
		byte qid = MainFrame.allocateQID();
		MagnetFrame mf = new MagnetFrame(qid, nw);
		mf.show();
		if (resultWins.size() <= (qid + 1))
			resultWins.setSize(qid+1);
		resultWins.setElementAt(mf,qid);
    }
	
    public void displayTopology() {
		if (topologyWindowUp)
			return;
		
		try {
			topologyFrame = new MainClass(nw, MainFrame.allocateQID());
		} catch (Exception e) { }
    }
	
    public void sendQuery() {
	    byte qid = MainFrame.allocateQID();
		
	    updateSQL();
	    TinyDBQuery curQuery = generateQuery(qid, epochDur);
	    if (curQuery == null)
			return;
	    curQuery.setSQL(sqlString.getText());
	    if (curQuery != null) {
			ResultFrame rf = new ResultFrame(curQuery, nw);
			
			rf.setLocation(5,30);
			if (logCheckBox.isSelected())
		    {
				try {
					DBLogger dbLogger = new DBLogger(curQuery, sqlString.getText(), nw);
				    // XXX keep track of this so we can delete the listener when the query is cancelled
					TinyDBMain.addQueryListener(dbLogger);
				} catch (SQLException e) {
					e.printStackTrace();
				}
		    }
			
			
			TinyDBMain.notifyAddedQuery(curQuery);
			
			rf.show();
			if (resultWins.size() <= (qid + 1))
				resultWins.setSize(qid+1);
			resultWins.setElementAt(rf,qid);
			if (TinyDBMain.debug) System.out.println(curQuery);
			try {
				nw.sendQuery(curQuery);
			} catch (IOException e) {
				e.printStackTrace();
			}
	    }
    }
	
    public void triggerCheckBoxAction() {
		if (triggerCheckBox.isSelected()) { //user selected the box
			if (checkSelectionConsistency(selectDestList,null)) {
				triggerActionBox.setEnabled(true);
				triggerLabel.setEnabled(true);
			} else {
				triggerCheckBox.setSelected(false);
			}
		} else { //user deselected the box
			if (checkSelectionConsistency(selectDestList,null)) {
				triggerActionBox.setEnabled(false);
				triggerLabel.setEnabled(false);
			} else {
				triggerCheckBox.setSelected(true);
			}
		}
		
		//update the aggregate operators available for the current source selection
		constrainAggregateChoices();
		
		//refresh the SQL clause to reflect this change
		updateSQL();
		
    }
    
    /** Called when the "-" button to remove a where clause is pressed */
    public void removeWhereButtonActionPerformed(ActionEvent evt, int panelId) {
		boolean removed = false;
		for (int i = 0; i < panels.length; i++) {
			if (!removed) {
				if (panels[i] != null && panels[i].getId() == panelId) {
					numPanels--;
					selectGroupPanel.remove(panels[i]);
					
					panels[i] = null;
					removed = true;
					validate();
				}
			} else {
				if (panels[i] != null) panels[i].setId(panels[i].getId() - 1);
				panels[i-1] = panels[i];
				panels[i] = null;
			}
		}
		repaint();
		updateSQL();
    }
    
    /** Called when the "<<<" to remove a selection attribute is clicked */
    private void removeSelButtonActionPerformed() {
	    Object value = selectDestList.getSelectedValue();
	    if (value != null) {
			Vector values = new Vector();
			ListModel model = selectDestList.getModel();
			for (int i = 0; i < model.getSize(); i++) {
				if(model.getElementAt(i) != value)
					values.addElement(model.getElementAt(i));
			}
			selectDestList.setListData(values);
	    }
	    updateSQL();
    }
    
    
    /** Called when the ">>>" to add a selection attribute is clicked */
    private void addSelButtonActionPerformed() {
	    QueryField value = (QueryField)selectSrcList.getSelectedValue();
	    AggOp op;
		
	    if (aggregateBox.getSelectedItem().toString().equals("None"))
			op = null;
	    else
			op = (AggOp)aggregateBox.getSelectedItem();
		
	    if (value != null) {
			SelectionField sf = new SelectionField(op, value);
			if (op == null || checkSelectionConsistency(selectDestList,sf)) {
				Vector values = new Vector();
				ListModel model = selectDestList.getModel();
				for (int i = 0; i < model.getSize(); i++) {
					values.addElement(model.getElementAt(i));
				}
				values.addElement(sf);
				selectDestList.setListData(values);
			}
	    }
	    updateSQL();
    }
    
    int oldIdx = -1;
    boolean oldGrouping = false;
    int oldGroupIdx = -1;
    
    
    /**
	 * Called when something happens in the attribute selection list --
	 * main goal is to constrain the aggregate operations menu so that
	 * only valid aggregate choices are available.
	 */
    private void constrainAggregateChoices() {
		int idx = selectSrcList.getMinSelectionIndex();
		boolean grouping = groupCheckBox.isSelected();
		int groupIdx = groupBox.getSelectedIndex();
		
		if (idx != oldIdx || grouping != oldGrouping || oldGroupIdx != groupIdx) {
			oldIdx = idx;
			oldGroupIdx = groupIdx;
			oldGrouping = grouping;
			
			updateSQL();
			
			constrainAggMenu(aggregateBox, grouping, groupIdx == idx, hasAgg());
		}
    }
    
    /** Limit the items available in the aggregation menu based
	 on whether we're grouping or not
	 */
    private void constrainAggMenu(JComboBox menu, boolean grouping, boolean groupbyField,  boolean hasAgg) {
	    menu.removeAllItems();
	    if (grouping && groupbyField) { //must not be an agg
			menu.addItem("None");
			return;
	    }
	    if (hasAgg || grouping) { //must be an agg
		    fillAggsFromCatalog(menu);
		    return;
		}
	    //either ok
	    menu.addItem("None");
	    fillAggsFromCatalog(menu);
		/**
		 for (int i = 0; i < aggs.length; i++) {
		 //else {
		 if (hasAgg || grouping) { //must be an agg
		 if (aggs[i] != null)
		 menu.addItem(aggs[i]);
		 } else {
		 if (aggs[i] == null)
		 menu.addItem("None");
		 else
		 menu.addItem(aggs[i]);
		 }
		 }
		 }**/
    }
    
    
    
    /** Called when the grouping check box is selected / deselected
	 Have to make sure that this is OK (can't have agg / non agg fields in same
	 if not grouping.
	 */
    private void groupCheckBoxAction(ActionEvent evt) {
		if (groupCheckBox.isSelected()) { //user selected the box
			if (checkSelectionConsistency(selectDestList,null)) {
				groupBox.setEnabled(true);
				groupLabel.setEnabled(true);
				groupByOps.setEnabled(true);
			} else {
				groupCheckBox.setSelected(false);
			}
		} else { //user deselected the box
			if (checkSelectionConsistency(selectDestList,null)) {
				groupBox.setEnabled(false);
				groupLabel.setEnabled(false);
				groupByOps.setEnabled(false);
				groupByConst.setEnabled(false);
			} else {
				groupCheckBox.setSelected(true);
			}
		}
		
		//update the attribute lists to reflect group by operators
		//updateAttributeLists();
		
		//update the aggregate operators available for the current source selection
		constrainAggregateChoices();
		
		//refresh the SQL clause to reflect this change
		updateSQL();
    }
    
    
    //User added a selection predicate -- create the new panel (if there's a slot for it.)
    private void newPredButtonActionPerformed(ActionEvent evt) {
		JPanel newPanel = null;
		
		if (numPanels < 3) {
			newPanel = new WherePanel(numPanels, this);
			panels[numPanels++] = (WherePanel)newPanel;
		} else {
			setError("At most three selection predicates allowed per query.");
		}
		
		if (newPanel != null) {
			selectGroupPanel.add(newPanel);
			
			validate();
		}
		
		
		repaint();
		updateSQL();
    }
    
    
    /** Add the available arithmetic operations to the menu */
    public void addArithOpsToMenu(JComboBox menu) {
		for (int i = 0; i < arithOps.length; i++) {
			menu.addItem(arithOps[i]);
		}
    }
    
    
    /** Add the available query fields (from the catalog) to the menu */
    public void addFieldsToMenu(JComboBox menu) {
		for (int i = 0; i < Catalog.curCatalog.numAttrs(); i++) {
			menu.addItem(Catalog.curCatalog.getAttr(i));
		}
    }
    
    /** Add the available selection operators to the specified menu */
    public void addOpsToMenu(JComboBox menu) {
		for (int i = 0; i < ops.length; i++) {
			menu.addItem(ops[i]);
		}
    }
    
    /** Add the vailable aggregate operators to the specified menu */
    private void addAggsToMenu(JComboBox menu) {
	    menu.addItem("None");
	    fillAggsFromCatalog(menu);
    }
    
    private void fillAggsFromCatalog(JComboBox menu) {
		for(Iterator it = Catalog.currentCatalog().getAggregates().iterator(); it.hasNext(); ) {
			AggregateEntry entry = (AggregateEntry)it.next();
			//only add those aggs that dont take any arguments
			if (entry.getArgCount() == 0) {
				menu.addItem(new AggOp(entry.getName()));
			}
	    }
	}
    
    /** Add the available epoch durations to the menu */
    private void addEpochsToMenu(JComboBox menu) {
		int es[] = {128,256,512,1024,2048,4096,8192,16384,32768,65536,131072,262144};
		for (int i =0 ; i < es.length; i++)
			menu.addItem(new Integer(es[i]));
		menu.setSelectedIndex(4);
    }
    
    
    /** Add the available selection attributes to the specific list */
    private void addSelectChoices(JList list) {
		Vector fields = new Vector();
		
		for (int i = 0; i < Catalog.curCatalog.numAttrs(); i++) {
			fields.add(Catalog.curCatalog.getAttr(i));
		}
		
		list.setListData(fields);
		
    }
    
    /** Given a list of current attrs in the query and a (possibly null) attr to add
	 to that list, return true iff the addition is OK (or newf == null) AND
	 the current settings (e.g. grouping, group by field, etc) are consistent.
	 
	 Return false otherwise.
	 
	 This is used extensively to determine if some user action produces a consistent
	 query.  It sets appropriate error messages when consistency checks fail.
	 */
    public boolean checkSelectionConsistency(JList list, SelectionField newf) {
		
		//is an agg -- check and see if there are any non-aggs in the list
		//if so, if we aren't grouping by them, ask the user what to do
		//if user wants to remove them, do so
		//otherwise, return false
		
		ListModel model = list.getModel();
		boolean hasAgg = hasAgg();
		boolean newAgg = newf != null && newf.getOp() != null;
		
		for (int i = 0; i < model.getSize(); i ++) {
			SelectionField sf = (SelectionField)model.getElementAt(i);
			boolean isGroupField = groupCheckBox.isSelected() && groupBox.getSelectedItem() == sf.getField();
			
			if (groupCheckBox.isSelected() && sf.getOp() == null && !isGroupField) {
				setError("Can't group if a non-aggregate field is present");
				return false;
			} else if (hasAgg && sf.getOp() == null && !isGroupField) {
				setError("Can't have non-aggregate field when other aggregates are present");
				return false;
			} else if ((!hasAgg && !isGroupField)  && (sf.getOp() != null || newAgg)) {
				setError("Can't have aggregate field when non-aggregates are present");
				return false;
			} else if (triggerCheckBox.isSelected() && sf.getOp() != null) {
				setError("Can't enabled triggers when aggregates are present");
				return false;
			}
			
			//else if (hasAgg && newAgg) {
			//	    setError("Only one aggregate allow per query in current implementation.");
			//	    return false;
			//	}
		}
		if (triggerCheckBox.isSelected() && newAgg) {
			setError("Can't add aggregates when triggering");
			return false;
		}
		return true;
    }
    
    //check and see if there are any aggs in the selection list
    public boolean hasAgg() {
		ListModel model = selectDestList.getModel();
		for (int i = 0; i < model.getSize(); i++) {
			SelectionField sf = (SelectionField)model.getElementAt(i);
			if (sf.getOp() != null) return true;
		}
		return false;
    }
    
    public void setError(String txt) {
		sqlString.setText(txt);
		setError = true;
    }
    
    /** Generate a SQL string for the current query */
    public void updateSQL() {
		String sql = "SELECT ";
		boolean first = true;
		
		if(setError) {
			setError = false;
			return;
		}
		
		ListModel model = selectDestList.getModel();
		
		if (model.getSize() == 0) {
			sql = "Query must SELECT at least one attribute.";
		} else {
			for (int i = 0; i < model.getSize(); i++) {
				SelectionField sf = (SelectionField)model.getElementAt(i);
				if (first) {
					sql += sf.toString();
					first = false;
				}      else
					sql += ", " + sf.toString();
			}
			sql += " FROM sensors ";
			first = true;
			for (int i = 0; i < panels.length; i++) {
				if (panels[i] != null) {
					if (first) {
						sql += "\nWHERE " + panels[i].toString();
						first = false;
					} else {
						sql += " AND " + panels[i].toString();
					}
					
				}
			}
			
			if (groupCheckBox.isSelected()) {
				Integer atten = (Integer)attenuationBox.getSelectedItem();
				
				sql += "\nGROUP BY " + groupBox.getSelectedItem().toString();
				
				String groupByOp = (String) groupByOps.getSelectedItem();
				
				if (!groupByOp.equals(""))
					sql += " " + groupByOp + " " + groupByConst.getText();
				//if (atten.intValue() == 0)
				//    sql += groupBox.getSelectedItem().toString();
				//else
				//    sql += "(" + groupBox.getSelectedItem().toString() + ">>" + atten + ")";
			}
			
			sql += "\nSAMPLE PERIOD " + epochDur;
			
			if (triggerCheckBox.isSelected()) {
				TriggerAction ta= (TriggerAction)triggerActionBox.getSelectedItem();
				
				sql += "\nTRIGGER ACTION " + ta.command;
				
				if (ta.hasParam)
					sql += "(" + ta.param +")";
			}
			
		}
		sqlString.setText(sql);
		
    }
    
    /** Make sure the attribute selections are consistent with the grouping
	 information. */
    void updateAttributeLists() {
		ListModel srcModel = selectSrcList.getModel(), destModel = selectDestList.getModel();
		Vector srcValues = new Vector(), destValues = new Vector();
		String groupField = groupBox.getSelectedItem().toString();
		String arithOp = (String) groupByOps.getSelectedItem();
		String arithConst = null;
		
		if (!arithOp.equals("")) {
			arithConst = groupByConst.getText();
		} else {
			arithOp = null;
		}
		
		SelectionField cur;
		int i;
		
		// make sure groupField appears as "groupField op const" iff the group by box is checked
		for (i = 0; i < srcModel.getSize(); i++) {
			cur = (SelectionField) srcModel.getElementAt(i);
			
			if (cur.equals(groupField)) {
				if (groupCheckBox.isSelected()) {
					cur.setArithOp(arithOp);
					cur.setArithConst(arithConst);
				}
			}
			srcValues.addElement(cur);
		}
		selectSrcList.setListData(srcValues);
		
		for (i = 0; i < destModel.getSize(); i++) {
			cur = (SelectionField) destModel.getElementAt(i);
			
			if (cur.equals(groupField)) {
				if (groupCheckBox.isSelected()) {
					cur.setArithOp(arithOp);
					cur.setArithConst(arithConst);
				}
			}
			destValues.addElement(cur);
		}
		selectDestList.setListData(destValues);
    }
	
    
    
    /** Generate a TinyDBQuery to represent the currently selected query
	 fields
	 */
    TinyDBQuery generateQuery(byte queryId, int epochDur) {
		ListModel model = selectDestList.getModel();
		
		if (model.getSize() == 0)
			return null;
		
		if (!checkSelectionConsistency(selectDestList, null)) return null;
		
		if (TinyDBMain.debug) System.out.println("Running query:  " + sqlString.getText());
		if (TinyDBMain.debug) System.out.println("Query ID = " + queryId);
		
		
		TinyDBQuery query = null;
		try {
			query = SensorQueryer.translateQuery(sqlString.getText(), queryId);
		} catch (ParseException pe) {
			System.err.println(pe.getMessage());
			if (TinyDBMain.debug) {
				pe.printStackTrace();
				System.err.println(pe.getParseError());
			}
			sqlString.setText(pe.getParseError());
		}
		
		
		return (query);
    }
    
	
    /** CatalogListener method called when a new attribute gets added */
    public void addedAttr(QueryField qf) {
		System.out.println("NEW ATTRIBUTE: " + qf);
		Vector values = new Vector();
		ListModel model = selectSrcList.getModel();
		for (int i = 0; i < model.getSize(); i++) {
			if (!((QueryField)model.getElementAt(i)).getName().equals(qf.getName()))
				values.addElement(model.getElementAt(i));
		}
		values.addElement(qf);
		selectSrcList.setListData(values);
    }
    
    private int numSelects = 0;
    public static boolean topologyWindowUp = false;
    private MainClass topologyFrame;
    
    private JList selectDestList;
    private JPanel groupByPanel;
    
    private JButton removeSelButton;
    private JSeparator jSeparator2;
    private JPanel selectGroupPanel;
    
    private JLabel groupLabel;
	
    private JButton newPredButton;
    
    private JComboBox groupBox;
    private JComboBox epochBox;
    private JComboBox attenuationBox;
    
    private JComboBox aggregateBox;
    private JLabel selectedLabel;
    private JButton addSelButton;
    private JLabel selectFieldsLabel;
    private JTextArea sqlString;
    private JList selectSrcList;
    private JCheckBox groupCheckBox;
    private JComboBox groupByOps;
    private JTextField groupByConst;
    
    private JCheckBox logCheckBox;
    private JPanel triggerPanel;
    private JLabel triggerLabel;
    private JCheckBox triggerCheckBox;
    private JComboBox triggerActionBox;
    private TriggerAction triggerActions[] = {new TriggerAction("Toggle Red Led", "SetLedR", true, (short)0x0202),
			new TriggerAction("Toggle Yellow Led", "SetLedY", true, (short)0x0202),
			new TriggerAction("Toggle Green Led", "SetLedG", true, (short)0x0202),
			new TriggerAction("Sounder (100ms)", "SetSnd", true, (short)100),
			new TriggerAction("Sounder (500ms)", "SetSnd", true, (short)500),
			new TriggerAction("Sounder (1000ms)", "SetSnd", true, (short)1000)};
    
    private SelOp eq = new SelOp(SelOp.OP_EQ);
    private SelOp neq = new SelOp(SelOp.OP_NEQ);
    private SelOp gt = new SelOp(SelOp.OP_GT);
    private SelOp ge = new SelOp(SelOp.OP_GE);
    private SelOp lt = new SelOp(SelOp.OP_LT);
    private SelOp le = new SelOp(SelOp.OP_LE);
    
	/*  private AggOp min = AggOp.makeAggregate(AggOp.AGG_MIN);
	 private AggOp max = AggOp.makeAggregate(AggOp.AGG_MAX);
	 private AggOp sum = AggOp.makeAggregate(AggOp.AGG_SUM);
	 private AggOp avg = AggOp.makeAggregate(AggOp.AGG_AVERAGE);
	 private AggOp cnt = AggOp.makeAggregate(AggOp.AGG_COUNT);
	 */
    private String arithOps[] = {"","+","-","*","/","%",">>"};
    private SelOp ops[] = {eq,neq,gt,ge,lt,le};
	// private AggOp aggs[] = {null, min,max,sum,avg,cnt};
    private Integer attens[] = {new Integer(0),
			new Integer(1),
			new Integer(2),
			new Integer(3),
			new Integer(4),
			new Integer(5),
			new Integer(6),
			new Integer(7),
			new Integer(8),
			new Integer(9),
			new Integer(10)};
    
	
    int numPanels = 0;
    WherePanel panels[] = new WherePanel[3];
    boolean setError = false;
    Object oldGroup;
    
    int epochDur = 2048;
    
    Vector resultWins = new Vector();
    boolean sendingQuery = false;
    boolean logQueryToDB = true;
    
    TinyDBNetwork nw;
    
    
    private Font normalFont = Font.decode("dialog-18");
    private Font textBoxFont = Font.decode("serif-16");
    private Font boldFont = Font.decode("dialog-bold-18");
    private Font bigFont = Font.decode("dialog-bold-18");
    private Font underlineFont = Font.decode("dialog-underline");
}

class SelectionField {
    public SelectionField(AggOp op, QueryField field) {
		this.op = op;
		this.field = field;
    }
    
    public AggOp getOp() {
		return op;
    }
    
    public QueryField getField() {
		return field;
    }
	
    public String toString() {
		if (op == null)
			return field.toString();
		else
			return op.toString() + "(" + field.toString() + ")";
    }
	
    public void setArithOp(String arithOp) {
		this.arithOp = arithOp;
    }
	
    public void setArithConst(String arithConst) {
		this.arithConst = arithConst;
    }
	
    String arithOp = null, arithConst = null;
    AggOp op;
    QueryField field;
}


class WherePanel extends JPanel {
    static final int BUT_SEP = 10;
    static final int ATTR_POPUP_WID = 120;
    static final int FIELD_OP_BOX_WID = 60;
    static final int FIELD_CONST_WID = 60;
    static final int WHERE_LABEL_LEFT = 30;
    static final int BUT_HEIGHT = 30;
    
    static final int WHERE_WID = 60;
    static final int WHERE_ATTR_LEFT = WHERE_LABEL_LEFT + WHERE_WID + BUT_SEP;
    static final int FIELD_OP_BOX_LEFT = WHERE_ATTR_LEFT + ATTR_POPUP_WID;
    static final int FIELD_CONST_LEFT = FIELD_OP_BOX_LEFT + FIELD_OP_BOX_WID;
    
    static final int OP_BOX_LEFT = FIELD_CONST_LEFT + FIELD_CONST_WID;
    static final int OP_BOX_WIDTH = 60;
    static final int CONSTANT_BOX_LEFT = OP_BOX_LEFT + OP_BOX_WIDTH;
    static final int CONSTANT_BOX_WID = 60;
    static final int SELECT_PANEL_WID = CONSTANT_BOX_LEFT + CONSTANT_BOX_WID;
    static final int RMV_WHERE_WID = 50;
    
    //build a selection panel
    public WherePanel(int panelId, final GuiPanel parent) {
		
		this.panelId = panelId;
		this.parent = parent;
		constantField = new JTextField();
		innerPanel = new JPanel();
		whereLabel = new JLabel();
		attributeBox = new JComboBox();
		attributeBox.setLightWeightPopupEnabled(false);
		parent.addFieldsToMenu(attributeBox);
		
		fieldOpBox = new JComboBox();
		fieldOpBox.setLightWeightPopupEnabled(false);
		parent.addArithOpsToMenu(fieldOpBox);
		fieldOpBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						JComboBox cb = (JComboBox)evt.getSource();
						String op = (String)cb.getSelectedItem();
						if (!op.equals("")) {
							fieldConst.setEnabled(true);
						} else {
							fieldConst.setEnabled(false);
						}
						parent.updateSQL();
					}
				});
		
		fieldConst = new JTextField();
		fieldConst.setEnabled(false);
		fieldConst.getDocument().addDocumentListener(new DocumentListener() {
					public void changedUpdate(DocumentEvent e){
						parent.updateSQL();
					}
					public void insertUpdate(DocumentEvent e){
						parent.updateSQL();
					}
					public void removeUpdate(DocumentEvent e){
						parent.updateSQL();
					}
				});
		
		
		opBox = new JComboBox();
		opBox.setLightWeightPopupEnabled(false);
		parent.addOpsToMenu(opBox);
		
		removeWhereButton = new JButton();
		
		setLayout(new AbsoluteLayout());
		
		//      setBackground(java.awt.Color.white);
		innerPanel.setLayout(new AbsoluteLayout());
		
		//      innerPanel.setBackground(java.awt.Color.white);
		whereLabel.setHorizontalAlignment(SwingConstants.CENTER);
		whereLabel.setText("WHERE");
		
		innerPanel.add(whereLabel, new AbsoluteConstraints(WHERE_LABEL_LEFT, 5, -1, -1));
		innerPanel.add(attributeBox, new AbsoluteConstraints(WHERE_ATTR_LEFT, 0, ATTR_POPUP_WID, BUT_HEIGHT));
		attributeBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						parent.updateSQL();
					}
					
				});
		
		innerPanel.add(fieldOpBox, new AbsoluteConstraints(FIELD_OP_BOX_LEFT, 0, FIELD_OP_BOX_WID, BUT_HEIGHT));
		innerPanel.add(fieldConst, new AbsoluteConstraints(FIELD_CONST_LEFT, 0, FIELD_CONST_WID, BUT_HEIGHT));
		
		innerPanel.add(opBox, new AbsoluteConstraints(OP_BOX_LEFT, 0, OP_BOX_WIDTH, BUT_HEIGHT));
		opBox.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						parent.updateSQL();
					}
					
				});
		
		
		constantField.getDocument().addDocumentListener(new DocumentListener() {
					public void changedUpdate(DocumentEvent e){
						parent.updateSQL();
					}
					public void insertUpdate(DocumentEvent e){
						parent.updateSQL();
					}
					public void removeUpdate(DocumentEvent e){
						parent.updateSQL();
					}
				});
		
		innerPanel.add(constantField, new AbsoluteConstraints(CONSTANT_BOX_LEFT, 0, CONSTANT_BOX_WID, BUT_HEIGHT));
		add(innerPanel, new AbsoluteConstraints(0, 0, SELECT_PANEL_WID, BUT_HEIGHT));
		removeWhereButton.setText("-");
		removeWhereButton.setToolTipText("Delete This Predicate");
		removeWhereButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent evt) {
						removeWhereButton(evt);
					}
				});
		
		add(removeWhereButton, new AbsoluteConstraints(SELECT_PANEL_WID, 0, RMV_WHERE_WID, BUT_HEIGHT));
    }
    
    private void removeWhereButton(ActionEvent evt) {
		parent.removeWhereButtonActionPerformed(evt,this.panelId);
    }
    
    private void constantFieldActionPerformed(ActionEvent evt) {
    }
    
    public String toString() {
		String str = "";
		
		str += attributeBox.getSelectedItem().toString() + " ";
		
		if (!getFieldOp().equals(""))
			str += getFieldOp() + " " + getFieldConst() + " ";
		
		str += opBox.getSelectedItem().toString() + " " + constantField.getText();
		
		return str;
    }
	
    public String getFieldConst() {
		return fieldConst.getText();
    }
	
    public String getFieldOp() {
		return ((String) fieldOpBox.getSelectedItem());
    }
	
    public QueryField getField() {
		return (QueryField)attributeBox.getSelectedItem();
    }
    
    public SelOp getOp() {
		return (SelOp)opBox.getSelectedItem();
    }
    
    public short getConstant() throws NumberFormatException {
		Short constant = new Short(constantField.getText());
	    return constant.shortValue();
    }
    
    public void setId(int id) {
	    panelId = id;
    }
    
    public int getId() {
	    return panelId;
    }
    
    JPanel innerPanel;
    JLabel whereLabel;
    JComboBox opBox;
    JComboBox attributeBox;
    JTextField constantField;
    JButton removeWhereButton;
    
    JComboBox fieldOpBox;
    JTextField fieldConst;
    
    int panelId;
    
    final GuiPanel parent;
}

class TriggerAction {
    public String name;
    public String command;
    public boolean hasParam = false;
    public short param;
    
    public TriggerAction(String name, String command, boolean hasParam, short param) {
		this.name = name;
		this.command = command;
		this.hasParam = hasParam;
		this.param = param;
    }
    
    public String toString() {
		return name;
    }
}
