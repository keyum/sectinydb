// $Id: MagnetFrame.java,v 1.4 2003/10/07 21:46:07 idgay Exp $

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
import net.tinyos.tinydb.parser.*;

/** MagnetFrame is a simple visualization to display an XDIM x YDIM array
    that represent a grid of sensors and to darken circles representing
    sensors whose magnetometer readings go above some threshold.
    
    MagnetFrame runs a simple query of the form
    
    SELECT nodeid, mag_x FROM sensors WHERE mag_x > THRESH 
    EPOCH DURATION 256

*/
public class MagnetFrame extends ResultFrame implements Runnable{
    static final int XDIM = 4;
    static final int YDIM = 3;
    static final int THRESH = 800;
	static final String magQueryText = "select mag_x, nodeid where mag_x > " + THRESH + " epoch duration 256";

    short[][] reading = new short[XDIM][YDIM];
    boolean[][] changed = new boolean[XDIM][YDIM];
    int epochNo = 0;


    /** Create the frame */
    public MagnetFrame(byte qid, TinyDBNetwork nw) {
	Thread t = new Thread(this);

	this.nw = nw;
	try
	{
		System.out.println("Magnet Demo Query: " + magQueryText);
		this.query = SensorQueryer.translateQuery(magQueryText, qid);
	}
	catch (ParseException pe)
	{
		System.out.println("Magnet Demo Query: " + magQueryText);
		System.out.println("Parse Error: " + pe.getParseError());
		this.query = null;
	}
	nw.addResultListener(this, false, query.getId());
	TinyDBMain.notifyAddedQuery(query);
	try {
	    nw.sendQuery(query);
	    t.start();
	} catch(java.io.IOException e) {
	    e.printStackTrace();
	}

	addWindowListener(new WindowAdapter() {
		public void windowClosing(WindowEvent evt) {
		    exitForm(evt);
		}
	    });
	
	setSize(400,400);
	
	
    }


    /** Background thread to periodically check if any new readings have
	arrived and update the visualization accordingly 
    */
    public void run() {
	while(true) {
	try {
	    Thread.currentThread().sleep(768);

		for (int i = 0; i < XDIM; i++) {
		    for (int j = 0; j < YDIM; j++) {
			if (!changed[i][j]) {
			    reading[i][j] = (short)THRESH;
			    this.repaint(16);
			} else
			    changed[i][j] = false;
		    }
		}

	} catch (Exception e) {
	}
	}
    }

    /** A new sensor value arrived -- indicate that the responding sensor's circle
	needs to be illuminated
    */
    public void addResult(QueryResult qr) {

	int x,y;
	Vector rv = qr.resultVector();

	if (qr.epochNo() > epochNo)
	    epochNo = qr.epochNo();

	if (rv.size() == 3) { //correct number of results? (first result is epoch)
	    int sid = new Integer((String)rv.elementAt(2)).intValue() - 1;
	    int light = new Integer((String)rv.elementAt(1)).intValue();

	    //find the x & y coords of the responding sensor
	    y = sid/XDIM;
	    x = sid - (y * XDIM);
	    
	    changed[x][y] = true;
	    System.out.println("LIGHT VALUE FOR SENSOR " + sid + " = " + light);

	    if (reading[x][y] != (short)light) {
		reading[x][y] = (short)light;
		this.repaint(16);
	    }
	}

    }

    public int getEpoch() {
	return epochNo;
    }

    public TinyDBQuery getQuery() {
	return query;
    }

    Image offScreenBuffer;

    public void update(Graphics g) {
	Graphics gr; 
	// Will hold the graphics context from the offScreenBuffer.
	// We need to make sure we keep our offscreen buffer the same size
	// as the graphics context we're working with.
	if (offScreenBuffer==null ||
	    (! (offScreenBuffer.getWidth(this) == this.size().width
                && offScreenBuffer.getHeight(this) == this.size().height)))
	    {
		offScreenBuffer = this.createImage(size().width, size().height);
	    }
	
	// We need to use our buffer Image as a Graphics object:
	gr = offScreenBuffer.getGraphics();
	
	paint(gr); // Passes our off-screen buffer to our paint method, which,
	// unsuspecting, paints on it just as it would on the Graphics
	// passed by the browser or applet viewer.
	g.drawImage(offScreenBuffer, 0, 0, this);
	// And now we transfer the info in the buffer onto the
	// graphics context we got from the browser in one smooth motion.
    }

    
    public void paint(Graphics g) {
	int xsize = getWidth(), ysize = getHeight();
	int xcellsize = xsize / XDIM, ycellsize = ysize / YDIM;

	g.clearRect(0,0,xsize, ysize);
	g.drawRect(0,0,xsize,ysize);

	for (int i = 1; i < XDIM; i++) {
	    g.drawLine(i * xcellsize, 0, i * xcellsize, ysize);
	}

	for (int i = 1; i < YDIM; i++) {
	    g.drawLine(0, i * ycellsize, xsize, i * ycellsize);
	}

	for (int i = 0; i < XDIM; i++) {
	    for (int j = 0; j < YDIM; j++) {
		int x = (int)(i * xcellsize + .25 * xcellsize);
		int y = (int)(j * ycellsize  + .25 * ycellsize);
		int xrad = (int)(.5 * xcellsize);
		int yrad = (int)(.5 * ycellsize);
		float cval = reading[i][j] > THRESH?.01f:.99f;
		if (cval > 0 && cval < 1) {
		    Color c = new Color(cval, cval, cval);
		    g.setColor(c);
		    g.fillOval(x,y,xrad,yrad);
		}
		g.setColor(Color.black);
		g.drawOval(x,y,xrad,yrad);
	    }

	}

    }

    
}
