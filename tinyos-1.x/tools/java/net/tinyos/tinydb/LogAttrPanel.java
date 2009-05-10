// $Id: LogAttrPanel.java,v 1.3 2003/10/07 21:46:07 idgay Exp $

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
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;
import net.tinyos.message.*;

/** LogAttrPanel displays a dialog that allows a user to specify 
 * an attribute name, a sample period and the number of samples to be
 * logged.  The result is a Message data structure for the logattr command
 * which can be injected into the network to log the attribute values
 * in EEPROM.
<p>
A logattr command needs three arguments:
<ol>
<li> name: (up to) 8 characters of attribute name
<li> samplePeriod: sample period in milliseconds
<li> nsamples: the number of samples to log
</ol>
@author Wei Hong (whong@intel-research.net)
*/
public class LogAttrPanel extends JDialog {
    boolean done;
    boolean ok;

    FixedSizeField attrName = new FixedSizeField(8);
  NumberField samplePeriod = new NumberField(10);
  NumberField nsamples = new NumberField(5);
  JLabel nameLabel = new JLabel("Attribute Name: ");
  JLabel samplePeriodLabel = new JLabel("Sample Period: ");
  JLabel nsamplesLabel = new JLabel("Number of Samples: ");
  JPanel namePanel = new JPanel(new GridLayout(1,2));
  JPanel samplePeriodPanel = new JPanel(new GridLayout(1,2));
  JPanel nsamplesPanel = new JPanel(new GridLayout(1,2));
  JLabel title = new JLabel("Specify parameters for attribute logging:    ");
  JPanel buttonPanel = new JPanel(new GridLayout(1,3));
  JButton okButton = new JButton("OK");
  JButton cancelButton = new JButton("Cancel");
  

    /** Constructor -- owner is the window that is causing the 
	addition
    */
    public LogAttrPanel(Frame owner) {
	super(owner,true);
	done= false;
    }

    /** Display the dialog 
	@return null if request was cancelled, otherwise the message
	that will add the new attribute
    */
   Message askForCommand(short receiver) {
     Message cmd = null;
       initComponents();
       show();

       if (ok) {	   
	    cmd = CommandMsgs.logAttrCmd(receiver,
					 attrName.getText().toCharArray(), 
					 new Long(samplePeriod.getText()).longValue(),
					 new Short(nsamples.getText()).shortValue());
       }

       
       return cmd;
    }

    private void done(boolean ok) {
	this.ok = ok;
	done = true;
	dispose();
    }


    private void initComponents() {
	JDialog frame = this;

	buttonPanel.add(new JLabel()); //dummy
	buttonPanel.add(cancelButton);
	buttonPanel.add(okButton);
		       
	attrName.setText("light");
	namePanel.add(nameLabel);
	namePanel.add(attrName);
	
	samplePeriod.setText("1024");
	samplePeriodPanel.add(samplePeriodLabel);
	samplePeriodPanel.add(samplePeriod);

	nsamples.setText("100");
	nsamplesPanel.add(nsamplesLabel);
	nsamplesPanel.add(nsamples);

	frame.getContentPane().setLayout(new GridLayout(6,1));
	frame.getContentPane().add(title);
	frame.getContentPane().add(namePanel);
	frame.getContentPane().add(samplePeriodPanel);
	frame.getContentPane().add(nsamplesPanel);
	frame.getContentPane().add(new JLabel()); //blank space
	frame.getContentPane().add(buttonPanel);

	okButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    done(true);
		}
	    });

	cancelButton.addActionListener( new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    done(false);
		}
	    });
				    
	
	frame.pack();
    }

    /** Test routine */
    public static void main(String[] argv) {
	AddAttrPanel p = new AddAttrPanel(null);
	p.askForCommand((short)-1);

    }
}
