// $Id: CmdFrame.java,v 1.6 2003/10/07 21:46:07 idgay Exp $

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

/** Command frame presents a simple UI for sending
    a variety of TinyDB control messages into the
    network.  See CommandMsgs for more info.
    
    @author smadden
*/
public class CmdFrame extends JFrame {
    static final short BCAST_ADDR = (short)-1;
    MoteIF mif;

    public CmdFrame(MoteIF mif) {
	super("Mote Commands");

	this.mif=mif;

	JButton resetButton = new JButton("Reset Motes");
	// JButton useFixedCommButton = new JButton("Fix Communication");
	// JButton unfixCommButton = new JButton("Unfix Communication");
	// JButton useFixedTopoButton = new JButton("Fix Topology");
	// JButton unfixTopoButton = new JButton("Unfix Topology");
	JButton setCommRadiusButton = new JButton("Set Radio Strength");
	JButton stopMagButton = new JButton("Stop Magnetometer");
	JButton chgBaseBcastIntvButton = new JButton("Change Base Bcast Interval");
	JButton sounderOnButton = new JButton("Sounder On");
	JButton addAttrButton = new JButton("Add Attribute");
	JButton logAttrButton = new JButton("Log Attribute");
	JButton fireTestEventButton = new JButton("Fire Test Event");
	JPanel moteIdPanel = new JPanel();
	Box box = Box.createVerticalBox();


	//getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
	
	buttonPanel.setLayout(new GridLayout(8,1));
	
	
	buttonPanel.add(resetButton);
	// buttonPanel.add(useFixedCommButton);
	// buttonPanel.add(unfixCommButton);
	// buttonPanel.add(useFixedTopoButton);
	// buttonPanel.add(unfixTopoButton);
	buttonPanel.add(setCommRadiusButton);
	buttonPanel.add(stopMagButton);
	buttonPanel.add(chgBaseBcastIntvButton);
	buttonPanel.add(sounderOnButton);
	buttonPanel.add(addAttrButton);
	buttonPanel.add(logAttrButton);
	buttonPanel.add(fireTestEventButton);

	moteIdPanel.setLayout(new GridLayout(2,1));
	moteIdPanel.add(broadcastBox);
	moteIdLabelPanel.setLayout(new GridLayout(1,2));
	moteIdLabelPanel.add(moteIdLabel);
	moteIdLabelPanel.add(moteID);
	moteIdPanel.add(moteIdLabelPanel);
	moteID.setText("0");
	moteID.setEnabled(false);
	moteIdLabel.setEnabled(false);
	moteIdLabel.setHorizontalAlignment(SwingConstants.RIGHT);
	broadcastBox.setSelected(true);
	broadcastBox.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    boolean en = broadcastBox.isSelected();
		    moteIdLabel.setEnabled(!en);
		    moteID.setEnabled(!en);
		}
	    });
				      

	box.add(buttonPanel);
	box.add(Box.createGlue());
	box.add(moteIdPanel);
	getContentPane().add(box);
	
	setSize(225,300);

	resetButton.addActionListener( new ActionListener() {
	    public void actionPerformed(ActionEvent evt) {
		sendMsg(CommandMsgs.resetCmd(rcptId()));
	    }
	  });

	/*
	useFixedCommButton.addActionListener( new ActionListener() {
	    public void actionPerformed(ActionEvent evt) {
		sendMsg(CommandMsgs.setFixedComm(BCAST_ADDR, true));
	    }
	  });

	unfixCommButton.addActionListener( new ActionListener() {
	    public void actionPerformed(ActionEvent evt) {
		sendMsg(CommandMsgs.setFixedComm(BCAST_ADDR, false));
	    }
	  });

        useFixedTopoButton.addActionListener( new ActionListener() {
	    public void actionPerformed(ActionEvent evt) {
		sendMsg(CommandMsgs.setFanout(BCAST_ADDR, (char)2));
	    }
	  });

	unfixTopoButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    sendMsg(CommandMsgs.setFanout(BCAST_ADDR, (char)0xFF));
	    }
	  });
	 */

	setCommRadiusButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {     
		    Object[] possibleValues = { new Integer(0), new Integer(10), new Integer(50), new Integer(90), new Integer(100) };
		    Object selectedValue = JOptionPane.showInputDialog(null,
								       "Select signal strength:", "Pot setting:",
								       JOptionPane.INFORMATION_MESSAGE, null,
								       possibleValues, possibleValues[1]);
		    if (selectedValue != null) 
			sendMsg(CommandMsgs.setPot(rcptId(), (char)((Integer)selectedValue).intValue()));
		}
	    });

	stopMagButton.addActionListener( new ActionListener() {
	    public void actionPerformed(ActionEvent evt) {
		sendMsg(CommandMsgs.stopMagCmd(rcptId()));
	    }
	  });

	chgBaseBcastIntvButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {     
		    Object[] possibleValues = { new Integer(125), new Integer(250), new Integer(500), new Integer(1000), new Integer(1700) };
		    Object selectedValue = JOptionPane.showInputDialog(null,
								       "Select Base Bcast Interval (millisec):", "Current Interval:",
								       JOptionPane.INFORMATION_MESSAGE, null,
								       possibleValues, new Integer(TinyDBNetwork.getBaseBcastInterval()));
		    if (selectedValue != null) 
			        TinyDBNetwork.setBaseBcastInterval(((Integer)selectedValue).intValue());
		}
	    });
	sounderOnButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {     
			sendMsg(CommandMsgs.setSounderCmd(rcptId()));
		}
	    });
	
	addAttrButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    doAddAttr();
		}
	    });
	
	logAttrButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    doLogAttr();
		}
	    });
	
	fireTestEventButton.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent evt) {
		    sendMsg(CommandMsgs.fireEvent(rcptId()));
		}
	    });

    }

    public static boolean isBcast() {
	return broadcastBox.isSelected();
    }

    public static short rcptId() {
	if (isBcast()) return BCAST_ADDR;
	return new Short(moteID.getText()).shortValue();
	
    }
    
    public void doAddAttr() {
	AddAttrPanel p = new AddAttrPanel(this);
	Message m = p.askForCommand(rcptId());
	if (m != null) {
	    sendMsg(m);
	    if (Catalog.curCatalog != null)
		Catalog.curCatalog.addAttr(p.getQueryField());
	}
    }

    public void doLogAttr() {
	LogAttrPanel p = new LogAttrPanel(this);
	Message m = p.askForCommand(rcptId());
	if (m != null) {
	    sendMsg(m);
	}
    }

    public void sendMsg(Message msg) {
	try {
	    System.out.print(msg);
	    System.out.println("");
	    mif.send( (short)-1,msg);
	} catch (Exception e) {
	    System.out.println("Error sending message.");
	    e.printStackTrace();
	}
    }

    static final JCheckBox broadcastBox = new JCheckBox("Broadcast");
    static JPanel moteIdLabelPanel = new JPanel();
    static final JLabel moteIdLabel = new JLabel("Target Id:");
    static final NumberField moteID = new NumberField(10);
    static JPanel buttonPanel = new JPanel();
    
}
