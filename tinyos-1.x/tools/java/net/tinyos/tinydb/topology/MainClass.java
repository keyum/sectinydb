// $Id: MainClass.java,v 1.6 2003/10/07 21:46:08 idgay Exp $

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
//this is the main class that holds all global variables
//and from where "main" is run.
//the global variables can be accessed as: MainClass.MainFrame for example.
//***********************************************************************
//***********************************************************************

package net.tinyos.tinydb.topology;

import java.util.*;
import net.tinyos.tinydb.*;
import net.tinyos.tinydb.topology.event.*;
import net.tinyos.tinydb.topology.util.*;
import net.tinyos.tinydb.topology.PacketAnalyzer.*;
import net.tinyos.tinydb.topology.Dialog.*;
import net.tinyos.tinydb.topology.Packet.*;
import javax.swing.event.*;
import java.beans.*;
import java.awt.*;
import java.io.*;
import net.tinyos.tinydb.parser.*;

public class MainClass implements ResultListener
{
	public static MainFrame mainFrame;
	public static DisplayManager displayManager;
	public static ObjectMaintainer objectMaintainer;
	public static SensorAnalyzer sensorAnalyzer;
	public static LocationAnalyzer locationAnalyzer;
	public static Vector packetAnalyzers;
	public static TinyDBQuery topologyQuery;
	public static boolean topologyQueryRunning = false;
	public static String topologyQueryText = "select nodeid, parent, light, temp, voltage epoch duration 2048";
    
    TinyDBNetwork nw;

	public MainClass(TinyDBNetwork nw, byte qid) throws IOException
	{
	    this.nw = nw;
	    nw.addResultListener(this, false, qid);

		mainFrame = new MainFrame("Sensor Network Topology", nw);
		displayManager = new DisplayManager(mainFrame);
			
		packetAnalyzers = new Vector();	
		
		objectMaintainer = new ObjectMaintainer();
		objectMaintainer.AddEdgeEventListener(displayManager);
		objectMaintainer.AddNodeEventListener(displayManager);
		
		locationAnalyzer = new LocationAnalyzer();
		sensorAnalyzer = new SensorAnalyzer();

		packetAnalyzers.add(objectMaintainer);
		packetAnalyzers.add(sensorAnalyzer);
			
	    //make the MainFrame visible as the last thing
		mainFrame.setVisible(true);
		try
		{
			System.out.println("Topology Query: " + topologyQueryText);
			topologyQuery = SensorQueryer.translateQuery(topologyQueryText, qid);
		}
		catch (ParseException pe)
		{
			System.out.println("Topology Query: " + topologyQueryText);
			System.out.println("Parse Error: " + pe.getParseError());
			topologyQuery = null;
		}
		nw.sendQuery(topologyQuery);
		TinyDBMain.notifyAddedQuery(topologyQuery);
		topologyQueryRunning = true;
	}


    public void addResult(QueryResult qr) {
	Packet packet = new Packet(qr);

	try {
	    
	    if (packet.getNodeId().intValue() < 0 || 
		packet.getNodeId().intValue() > 128 ||
		packet.getParent().intValue() < 0 ||
		packet.getParent().intValue() > 128 )
		return;
	} catch (ArrayIndexOutOfBoundsException e) {
	    return;
	}
	
	PacketEventListener currentListener;
	for(Enumeration list = packetAnalyzers.elements(); list.hasMoreElements();)
	    {
		currentListener = (PacketEventListener)list.nextElement();
		PacketEvent e = new PacketEvent(nw, packet,
						Calendar.getInstance().getTime());
		currentListener.PacketReceived(e);//send the listener an event
	    }			
    }
}
