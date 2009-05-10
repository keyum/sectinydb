// $Id: MainFrame.java,v 1.7 2003/10/07 21:46:07 idgay Exp $

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
import net.tinyos.tinydb.awtextra.*;

public class MainFrame extends JFrame {
    //Layout constants
    static final int TAB_PANE_WID = 575;  //width of the tabbed pane
    static final int BUT_SEP = 10; //seperator between buttons
    static final int FRAME_HEIGHT = 535;
    static final int BUT_PANEL_WID = 200;
    static final int BUT_HEIGHT = 30;
    
    static final int BUT_PANEL_LEFT = TAB_PANE_WID + BUT_SEP;
    static final int SEND_BUTTON_TOP = 25;
    static final int TOPO_BUTTON_TOP = SEND_BUTTON_TOP + BUT_HEIGHT + BUT_SEP;
    static final int MAGNET_BUTTON_TOP = TOPO_BUTTON_TOP + BUT_HEIGHT + BUT_SEP;
	
    static final int LOGO_WID= 128; //size of tinydb logo
    static final int LOGO_HEIGHT = 108;
	
    static final int LOGO_LEFT = 0;
    static final int LOGO_TOP = MAGNET_BUTTON_TOP + BUT_HEIGHT + BUT_SEP;
	
    static final int ROOT_ID_TOP = LOGO_TOP + LOGO_HEIGHT + BUT_SEP;
    static final int ROOT_ID_LABEL_LEFT = 0;
    static final int ROOT_ID_LABEL_WID = 70;
    static final int ROOT_ID_BOX_LEFT = ROOT_ID_LABEL_WID + BUT_SEP;
    static final int ROOT_ID_BOX_WID = 50;
	
    static final int QID_LABEL_WID = 100;
    static final int QID_BOX_LEFT = QID_LABEL_WID + BUT_SEP;
    static final int QID_TOP = ROOT_ID_TOP + BUT_HEIGHT + BUT_SEP;
	
    public MainFrame(TinyDBNetwork nw, boolean startGuiInterface) {
		super("Query Constructor");
		this.nw = nw;
		
		/*
		 KeyboardFocusManager kb = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		 kb.addKeyEventPostProcessor(nw);
		 */
		
		
		initComponents(startGuiInterface);
    }
	
    private void initComponents(boolean startGuiInterface) {
		addWindowListener(new WindowAdapter() {
					public void windowClosing(WindowEvent evt) {
						exitForm(evt);
					}
				});
		
		
		guiPanel = new GuiPanel(nw);
		textPanel = new TextPanel(nw);
		
		tabPanel = new JTabbedPane();
		tabPanel.addTab("Graphical Interface", guiPanel);
		tabPanel.addTab("Text Interface", textPanel);
		
		tabPanel.setSelectedIndex(startGuiInterface?0:1);
		
		sendButton = new JButton("Send Query");
		sendButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						if (tabPanel.getSelectedIndex() == 0)
							guiPanel.sendQuery();
						else if (tabPanel.getSelectedIndex() == 1)
							textPanel.sendQuery();
					}
				});
		
		displayTopologyButton = new JButton("Display Topology");
		displayTopologyButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						guiPanel.displayTopology();
					}
				});
		
		magnetDemoButton = new JButton("Magnet Demo");
		magnetDemoButton.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						guiPanel.magnetDemo();
					}
				});
		
		//Disabled 9.3.03 SRM -- root must always be id 0 in the current release
		//rootIdLabel = new JLabel("Root Id:");
		//rootIdBox = new NumberField(10);
		//rootIdBox.setText("0");
		
		nextQidLabel = new JLabel("Next QID:");
		nextQidBox = new NumberField(10);
		nextQidBox.setText(new Integer(curId).toString());
		
		
		buttonPanel = new JPanel(new AbsoluteLayout());
		buttonPanel.add(sendButton, new AbsoluteConstraints(0, SEND_BUTTON_TOP, -1, BUT_HEIGHT));
		buttonPanel.add(displayTopologyButton, new AbsoluteConstraints(0, TOPO_BUTTON_TOP, -1, BUT_HEIGHT));
		buttonPanel.add(magnetDemoButton, new AbsoluteConstraints(0, MAGNET_BUTTON_TOP, -1, BUT_HEIGHT));
		logoLabel = new JLabel(new ImageIcon("images/tinydblogo.jpg"));
		buttonPanel.add(logoLabel, new AbsoluteConstraints(LOGO_LEFT, LOGO_TOP, LOGO_WID, LOGO_HEIGHT));
		//SRM 9.3.03
		//buttonPanel.add(rootIdLabel, new AbsoluteConstraints(ROOT_ID_LABEL_LEFT, ROOT_ID_TOP, ROOT_ID_LABEL_WID, BUT_HEIGHT));
		//buttonPanel.add(rootIdBox, new AbsoluteConstraints(ROOT_ID_BOX_LEFT, ROOT_ID_TOP, ROOT_ID_BOX_WID, BUT_HEIGHT));
		buttonPanel.add(nextQidLabel, new AbsoluteConstraints(ROOT_ID_LABEL_LEFT, QID_TOP, QID_LABEL_WID, BUT_HEIGHT));
		buttonPanel.add(nextQidBox, new AbsoluteConstraints(QID_BOX_LEFT, QID_TOP, ROOT_ID_BOX_WID, BUT_HEIGHT));
		
		
		contentPane.setLayout(new AbsoluteLayout());
		contentPane.add(tabPanel, new AbsoluteConstraints(0, 0, TAB_PANE_WID, FRAME_HEIGHT));
		contentPane.add(buttonPanel, new AbsoluteConstraints(BUT_PANEL_LEFT, 0, BUT_PANEL_WID, FRAME_HEIGHT));
		
		
		
		
		pack();
    }
	
    /** Return the value of the rootId in the rootId field */
    public int getRootId() {
	return 0;
// SRM 9.3.03
//  		try {
//  			return new Integer(rootIdBox.getText()).intValue();
//  		} catch (NumberFormatException e) {
//  			//won't happen, since the field doesn't allow it, but...
//  			return 0;
//  		}
		
    }
	
    public static byte getNextQid() {
		try {
			return new Byte(nextQidBox.getText()).byteValue();
		} catch (NumberFormatException e) {
			//won't happen, since the field doesn't allow it, but...
			return 0;
		}
    }
    
    public static void setNextQid(byte qid) {
		curId = qid;
		if (nextQidBox != null) {
			nextQidBox.setText(new Byte(qid).toString());
		}
		
    }
    
    private void exitForm(WindowEvent evt) {
		System.exit(0);
    }
	
	
    /** Allocate a query ID for a new query
	 WARNING:  There could be serious problems here
	 on wrap-around.  We aren't dealing with this.
	 */
    public static byte allocateQID()
    {
		if (nextQidBox != null) {
			curId = getNextQid();
			nextQidBox.setText((new Byte((byte)(curId+1))).toString());
			return curId;
		} else {
			return curId++;
		}
		
    }
	
    GuiPanel guiPanel;
    TextPanel textPanel;
    
    TinyDBNetwork nw;
    Container contentPane = getContentPane();
    JTabbedPane tabPanel;
    JPanel buttonPanel;
    private JLabel logoLabel;
    JButton sendButton, displayTopologyButton, magnetDemoButton;
    static byte curId = 0;
    private JLabel /*rootIdLabel,*/ nextQidLabel;
    //private NumberField rootIdBox;
    private static NumberField nextQidBox = null;
	
}

