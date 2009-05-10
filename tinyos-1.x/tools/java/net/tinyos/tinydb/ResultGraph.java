// $Id: ResultGraph.java,v 1.2 2003/10/07 21:46:07 idgay Exp $

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

import ptolemy.plot.*;
import java.util.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class ResultGraph extends Plot {
    int lineWidth = 1;
    
    public ResultGraph(int lineWidth) {
	setSize(540,550);
	setVisible(true);
	this.lineWidth = lineWidth;
	_setPadding(.1);
    }

    public void addKey(int id, String label) {
      addLegend(id, label);
    }

    public void addPoint(int id, double time, int value) {
      addPoint(id, time, (double)value, true);
      repaint();
    }

    protected void _drawLine(java.awt.Graphics g,
			     int dataset,
			     long startx,
			     long starty,
			     long endx,
			     long endy,
			     boolean clip) 
    {
	Graphics2D g2d = null;
	Stroke oldStroke = null;

	if (g instanceof Graphics2D) {
	    g2d = (Graphics2D)g;
	    oldStroke = g2d.getStroke();
	    g2d.setStroke(new BasicStroke((float)lineWidth));
	}

	super._drawLine(g,dataset,startx,starty,endx,endy,clip);

	if (g instanceof Graphics2D) {
	    g2d.setStroke(oldStroke);
	}
    }

}
