// $Id: TabbedDialog.java,v 1.2 2003/10/07 21:46:08 idgay Exp $

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
 * @author Wei Hong
 */

//***********************************************************************
//***********************************************************************
//This is a standard dialog with a tabbed pane on it which can display
//as many ActivePanels as you like.  It is used for displaying both Node 
//and Edge information.
//***********************************************************************
//***********************************************************************
//It is created by DisplayManager when a node or edge is clicked.
//Each of the PacketAnalyzers provides an ActivePanel which is displayed
//on a unique tab on the dialog
//***********************************************************************
//***********************************************************************
//When the dialog is closed, it applys all the changes in the ActivePanels.
//When it is cancelled, it just closes.
//***********************************************************************
//***********************************************************************
//You must set the modal properties and title of the dialog manually.
//Otherwise, just use the same way as standard dialog.
//***********************************************************************
//***********************************************************************

package net.tinyos.tinydb.topology.Dialog;

import javax.swing.*;
import java.awt.*;
import net.tinyos.tinydb.topology.util.*;
import net.tinyos.tinydb.topology.Dialog.*;

              
              
public class TabbedDialog extends javax.swing.JDialog
{
	          //-----------------------------------------------------------------------
	          //CONSTRUCTORS
	public TabbedDialog(Frame parent)
	{
		super(parent);
		
		// This code is automatically generated by Visual Cafe when you add
		// components to the visual environment. It instantiates and initializes
		// the components. To modify the code, only use code syntax that matches
		// what Visual Cafe can generate, or Visual Cafe may be unable to back
		// parse your Java file into its visual environment.
		//{{INIT_CONTROLS
		setDefaultCloseOperation(javax.swing.JFrame.DISPOSE_ON_CLOSE);
		setModal(true);
		setTitle("DialogTitle");
		getContentPane().setLayout(null);
		setSize(312,359);
		setVisible(false);
		ApplyButton.setNextFocusableComponent(CancelButton);
		ApplyButton.setText("Apply");
		ApplyButton.setActionCommand("Apply");
		// getContentPane().add(ApplyButton);
		ApplyButton.setBounds(36,324,105,30);
		CancelButton.setText("Cancel");
		CancelButton.setActionCommand("Cancel");
		// getContentPane().add(CancelButton);
		CancelButton.setBounds(168,324,102,30);
		JTabbedPane1.setOpaque(true);
		getContentPane().add(JTabbedPane1);
		JTabbedPane1.setBounds(0,0,312,324);
		//}}
	
		//{{REGISTER_LISTENERS
		SymAction lSymAction = new SymAction();
		ApplyButton.addActionListener(lSymAction);
		CancelButton.addActionListener(lSymAction);
		//}}
	}

	public TabbedDialog()
	{
		this((Frame)null);
	}

	public TabbedDialog(String sTitle)
	{
		this();
		setTitle(sTitle);
	}
	          //CONSTRUCTORS
	          //-----------------------------------------------------------------------

	public void setVisible(boolean b)
	{
		if (b)
			setLocation(50, 50);
		super.setVisible(b);
	}
	
	          //-----------------------------------------------------------------------
	          //APPLY CHANGES
	          //this is what happens when "OK" is clicked
	public void ApplyChanges()
	{
		ActivePanel currentPanel;
		int numTabs = JTabbedPane1.getTabCount();
		for(int count = 0; count < numTabs; count++)
		{
			currentPanel = (ActivePanel)JTabbedPane1.getComponentAt(count);
			currentPanel.ApplyChanges();
		}
	}
	          //APPLY CHANGES
	          //-----------------------------------------------------------------------
	

	          //-----------------------------------------------------------------------
		      //ADD ACTIVE PANEL
	public void AddActivePanel(String name, ActivePanel pPanel)
	{
		if( (pPanel == null) ||
			(pPanel.GetCancelInfoDialog() == true))	
		{
			return;
		}
		pPanel.InitializeDisplayValues();
		if(name == null)
		{
			JTabbedPane1.add((Component)pPanel);
		}
		else
		{
			JTabbedPane1.add(name, (Component)pPanel);
		}
	}
	          //-----------------------------------------------------------------------
		      //ADD ACTIVE PANEL

	public void addNotify()
	{
		// Record the size of the window prior to calling parents addNotify.
		Dimension size = getSize();

		super.addNotify();

		if (frameSizeAdjusted)
			return;
		frameSizeAdjusted = true;

		// Adjust size of frame according to the insets
		Insets insets = getInsets();
		setSize(insets.left + insets.right + size.width, insets.top + insets.bottom + size.height);
	}

	// Used by addNotify
	boolean frameSizeAdjusted = false;

	//{{DECLARE_CONTROLS
	javax.swing.JButton ApplyButton = new javax.swing.JButton();
	javax.swing.JButton CancelButton = new javax.swing.JButton();
	javax.swing.JTabbedPane JTabbedPane1 = new javax.swing.JTabbedPane();
	//}}


	class SymAction implements java.awt.event.ActionListener
	{
		public void actionPerformed(java.awt.event.ActionEvent event)
		{
			Object object = event.getSource();
			if (object == ApplyButton)
				ApplyButton_actionPerformed(event);
			else if (object == CancelButton)
				CancelButton_actionPerformed(event);
		}
	}

	void ApplyButton_actionPerformed(java.awt.event.ActionEvent event)
	{
		// to do: code goes here.
			 
		ApplyButton_actionPerformed_Interaction1(event);
	}

	void ApplyButton_actionPerformed_Interaction1(java.awt.event.ActionEvent event)
	{
		try {
			this.ApplyChanges();
			this.dispose();		
		} catch (java.lang.Exception e) {
		}
	}

	void CancelButton_actionPerformed(java.awt.event.ActionEvent event)
	{
		// to do: code goes here.
			 
		CancelButton_actionPerformed_Interaction1(event);
	}

	void CancelButton_actionPerformed_Interaction1(java.awt.event.ActionEvent event)
	{
		try {
			this.dispose();
		} catch (java.lang.Exception e) {
		}
	}
	

}
