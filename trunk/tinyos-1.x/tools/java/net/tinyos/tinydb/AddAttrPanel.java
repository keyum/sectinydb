// $Id: AddAttrPanel.java,v 1.3 2003/10/07 21:46:07 idgay Exp $

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

/** AddAttrPanel displays a dialog that allows a user to specify a new
(constant valued) attribute to add to the catalog.  The result is a
Message data structure which can be injected into the network to add
the attribute.  
<p>
A new attribute consists of three fields:
<ol>
<li> name: (up to) 8 bytes of name
<li> type: a tinydb type (except String) from QueryField
<li> value: a constant value (up to 4 bytes in size)
</ol>
@author Sam Madden (madden@cs.berkeley.edu)
*/
public class AddAttrPanel extends JDialog {
    boolean done;
    boolean ok;


    TinyDBType[] types = {new TinyDBType(QueryField.INTONE,"int8_t"),
				       new TinyDBType(QueryField.UINTONE,"uint8_t"),
				       new TinyDBType(QueryField.INTTWO,"int16_t"),
				       new TinyDBType(QueryField.UINTTWO,"uint16_t"),
				       new TinyDBType(QueryField.INTFOUR,"int32_t"),
				       new TinyDBType(QueryField.UINTFOUR,"uint32_t"),
				       new TinyDBType(QueryField.TIMESTAMP,"timestamp")
				      };

    FixedSizeField attrName = new FixedSizeField(8);
  JComboBox type = new JComboBox(types);
  NumberField attrValue = new NumberField(10);
  JLabel nameLabel = new JLabel("Attribute Name: ");
  JLabel valueLabel = new JLabel("Attribute Value: ");
  JLabel typeLabel = new JLabel("Attribute Type: ");
  JPanel namePanel = new JPanel(new GridLayout(1,2));
  JPanel valuePanel = new JPanel(new GridLayout(1,2));
  JPanel typePanel = new JPanel(new GridLayout(1,2));
  JLabel title = new JLabel("Specify a new constant attribute:    ");
  JPanel buttonPanel = new JPanel(new GridLayout(1,3));
  JButton okButton = new JButton("OK");
  JButton cancelButton = new JButton("Cancel");
  

    /** Constructor -- owner is the window that is causing the 
	addition
    */
    public AddAttrPanel(Frame owner) {
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
	    cmd = CommandMsgs.addAttrCmd(receiver,
					 attrName.getText().toCharArray(), 
					 (byte)types[type.getSelectedIndex()].type, 
					 new Long(attrValue.getText()).longValue());
       }

       
       return cmd;
    }

    /** @return The query field that the user just entered , or NULL if the user clicked 'cancel' */
    public QueryField getQueryField() {
	if (ok) {
	    QueryField qf = new QueryField(attrName.getText(), (byte)types[type.getSelectedIndex()].type);
	    return qf;
	} else return null;
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
		       
	attrName.setText("attr");
	namePanel.add(nameLabel);
	namePanel.add(attrName);
	
	attrValue.setText("0");
	valuePanel.add(valueLabel);
	valuePanel.add(attrValue);


	typePanel.add(typeLabel);
	typePanel.add(type);
	

	frame.getContentPane().setLayout(new GridLayout(6,1));
	frame.getContentPane().add(title);
	frame.getContentPane().add(namePanel);
	frame.getContentPane().add(typePanel);
	frame.getContentPane().add(valuePanel);
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

    /* ------------- Internal classes ------------- */
			  
    class TinyDBType {
	int type;
	String name;
	public TinyDBType(int type, String name) {
	    this.type = type;
	    this.name = name;
	}
	public String toString() {
	    return name;
	}
    }
   


}
