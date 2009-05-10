// $Id: LocationAnalyzer.java,v 1.2 2003/10/07 21:46:08 idgay Exp $

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

package net.tinyos.tinydb.topology.PacketAnalyzer;

import net.tinyos.tinydb.topology.*;
import net.tinyos.tinydb.topology.event.*;
import net.tinyos.tinydb.topology.util.*;
import net.tinyos.tinydb.topology.Dialog.*;
import java.util.*;
import java.lang.*;
import javax.swing.*;
import java.io.*;
import java.awt.*;
import net.tinyos.tinydb.topology.Packet.*;
              //this class performs two functions:
              // 1.  estimate distances between nodes
              // 2.  estimate the locations of the nodes
              //It is currently configured to be able to do these functions
              //using interchangable distance and location estimators
              
              //Basically, it estimates distance every time a new packet is recieved
              //and a seperate thread runs in the background, constantly updating 
              //the location estimates
public class LocationAnalyzer extends PacketAnalyzer implements java.lang.Runnable
{
	Thread estimateLocationThread;
	protected static Hashtable proprietaryNodeInfo;
	protected static TwoKeyHashtable proprietaryEdgeInfo;
	
	public LocationAnalyzer()
	{
		      //define hashtables to hold my proprietary information
		proprietaryNodeInfo = new Hashtable();
		proprietaryEdgeInfo = new TwoKeyHashtable();
		
		//register to hear new node and edge events
		MainClass.objectMaintainer.AddNodeEventListener(this);
		MainClass.objectMaintainer.AddEdgeEventListener(this);

		//register myself to recieve NodeClickedEvents and EdgeClickedEvents
		// MainClass.displayManager.AddNodeDialogContributor(this);
		// MainClass.displayManager.AddEdgeDialogContributor(this);

		      //register to be a node and edge painter
		// MainClass.displayManager.AddNodePainter(this);
		MainClass.displayManager.AddEdgePainter(this);
	}

		      //*****---PACKETRECIEVED EVENT HANDLER---*****//
	public  void PacketReceived(PacketEvent e)
	{
		      //this function will read the packet and update the lengths
		      //of the edges that correspond to the data in the packet.  
		Packet packet = e.GetPacket();
		double distance;
		EdgeInfo edgeInfo;
		Integer sourceNodeNumber, destinationNodeNumber;
		
		sourceNodeNumber = packet.getNodeId();
		destinationNodeNumber = packet.getParent();
		distance = -1;
		edgeInfo = (EdgeInfo)proprietaryEdgeInfo.get(sourceNodeNumber, destinationNodeNumber);
		if( (!Double.isNaN(distance)) && (edgeInfo!=null) )
		{	
			edgeInfo.SetDistance(distance);	
		}
	}
		      //*****---PACKETRECIEVED EVENT HANDLER---*****//
	          //----------------------------------------------------------------------
		      
	
	          //----------------------------------------------------------------------
		      //*****---run---*****//
	public void run() 
	{
		      //this function will do all background work for location estimation
		      //in general, this would include mass springs or boltzman machine
		      //type activity
		while(true)
		{	
			try
			{
				estimateLocationThread.sleep(100);
			}
			catch(Exception e){e.printStackTrace();}
			// just randomly assign locations
			NodeInfo currentNode;
			for(Enumeration nodes = GetNodeInfo(); nodes.hasMoreElements();) 
			{
				currentNode = (NodeInfo)nodes.nextElement();
				synchronized(currentNode)
				{
					if(currentNode.GetFixed() == false)
					{
							currentNode.SetX(Math.random());
						currentNode.SetY(Math.random());
						currentNode.SetFixed(true);
					}
				}
			}
		}
	}
			  //*****---run---*****//
	          //----------------------------------------------------------------------



	public  void NodeCreated(NodeEvent e)
    {
		Integer nodeNumber = e.GetNodeNumber();
    	proprietaryNodeInfo.put(nodeNumber, new NodeInfo(nodeNumber));
    }

    public  void NodeDeleted(NodeEvent e)
    {
		Integer nodeNumber = e.GetNodeNumber();
    	proprietaryNodeInfo.remove(nodeNumber);
    }
	
	public  void EdgeCreated(EdgeEvent e)
    {
		Integer sourceNodeNumber = e.GetSourceNodeNumber();
    	Integer destinationNodeNumber = e.GetDestinationNodeNumber();//you probably want to create a new info pbject to track the data of this new node
    	proprietaryEdgeInfo.put(sourceNodeNumber, destinationNodeNumber, new EdgeInfo(sourceNodeNumber, destinationNodeNumber));

    }
 
    public  void EdgeDeleted(EdgeEvent e)
    {
		Integer sourceNodeNumber = e.GetSourceNodeNumber();
    	Integer destinationNodeNumber = e.GetDestinationNodeNumber();//you probably want to create a new info pbject to track the data of this new node
    	proprietaryEdgeInfo.remove(sourceNodeNumber, destinationNodeNumber);
    }

    public  void NodeClicked(NodeClickedEvent e)
    {
    }

    public  void EdgeClicked(EdgeClickedEvent e)
    {
    }

	public void PaintNode(Integer pNodeNumber, int x1, int y1, int x2, int y2, Graphics g)
	{
		NodeInfo nodeInfo = (NodeInfo)proprietaryNodeInfo.get(pNodeNumber);
		if(nodeInfo==null) return;
		
		if(nodeInfo.GetDisplayCoords() == true)
		{
			String temp = String.valueOf(nodeInfo.GetX());
			String text = temp.substring(0,Math.min(4, temp.length()));
			text = text.concat(",");
			temp = String.valueOf(nodeInfo.GetY());
			text = text.concat(temp.substring(0,Math.min(4, temp.length())));
			g.setColor(Color.black);
			g.drawString(text,  x1, y1);
		}
	}
	
	public void PaintEdge(Integer pSourceNodeNumber, Integer pDestinationNodeNumber, int screenX1, int screenY1, int screenX2, int screenY2, Graphics g)
	{
		EdgeInfo edgeInfo = (EdgeInfo)proprietaryEdgeInfo.get(pSourceNodeNumber,pDestinationNodeNumber);
		if(edgeInfo == null) return;
	
		if(edgeInfo.GetRoutingPath()){
			g.setColor(Color.green);
			drawLine(g, screenX1, screenY1, screenX2, screenY2, 5);
		}
	
		if(edgeInfo.GetDisplayLength() == true)
		{
			String temp= String.valueOf(this.GetDistance(pSourceNodeNumber,pDestinationNodeNumber));
			String text = temp.substring(0,Math.min(3, temp.length()));
			text = text.concat(",");
			double x1 = GetX(pSourceNodeNumber);
			double y1 = GetY(pSourceNodeNumber);
			double x2 = GetX(pDestinationNodeNumber);
			double y2 = GetY(pDestinationNodeNumber);
			temp = String.valueOf(Math.sqrt(Math.pow(x1-x2, 2)+ Math.pow(y1-y2, 2)));
			text = text.concat(temp.substring(0,Math.min(3, temp.length())));//put both estimated and real distances
			g.setColor(Color.black);
			g.drawString(text, (screenX2+screenX1)/2, (screenY2+screenY1)/2);
		}
	}
	
	public ActivePanel GetProprietaryNodeInfoPanel(Integer pNodeNumber)
	{
		return new ProprietaryNodeInfoPanel((NodeInfo)proprietaryNodeInfo.get(pNodeNumber));
	}

	public ActivePanel GetProprietaryEdgeInfoPanel(Integer pSourceNodeNumber, Integer pDestinationNodeNumber)
	{
		return new ProprietaryEdgeInfoPanel((EdgeInfo)proprietaryEdgeInfo.get(pSourceNodeNumber,pDestinationNodeNumber));
	}

              //----------------------------------------------------------------
              //GET/SET
    public double GetDistance(Integer sourceNodeNumber, Integer destinationNodeNumber )
    {
    	EdgeInfo edgeInfo = (EdgeInfo)proprietaryEdgeInfo.get(sourceNodeNumber, destinationNodeNumber);
    	if(edgeInfo != null)
    	{
    		return edgeInfo.GetDistance();
    	}
    	else
    	{
    		return Double.NaN;
    	}
    }
    
    public double GetX(Integer nodeNumber )
    {
    	NodeInfo nodeInfo = (NodeInfo)proprietaryNodeInfo.get(nodeNumber);
    	if(nodeInfo !=null)
    	{
    		return nodeInfo.GetX();
    	}
    	else
    	{
    		return Double.NaN;
    	}
    }
    public double GetY(Integer nodeNumber)
    {
    	NodeInfo nodeInfo = (NodeInfo)proprietaryNodeInfo.get(nodeNumber);
    	if(nodeInfo !=null)
    	{
    		return nodeInfo.GetY();
    	}
    	else
    	{
    		return -1;
    	}
    }
	public NodeInfo GetNodeInfo(Integer nodeNumber){return (NodeInfo)proprietaryNodeInfo.get(nodeNumber);}
	public EdgeInfo GetEdgeInfo(Integer sourceNumber, Integer destinationNumber){return (EdgeInfo)proprietaryEdgeInfo.get(sourceNumber,destinationNumber);}
	public Enumeration GetNodeInfo(){return proprietaryNodeInfo.elements();}
	public Enumeration GetEdgeInfo(){return proprietaryEdgeInfo.elements();}
		      
	public class NodeInfo
	{
		protected double x;
		protected double y;
		protected Integer nodeNumber;
		protected boolean fixed;//determines if the node can move around automatically or not
		protected boolean displayCoords;//determines if the XY Coords should be drawn
		
		public NodeInfo(Integer pNodeNumber)
		{
			nodeNumber = pNodeNumber;
			try{
				FileInputStream f = new FileInputStream("temp/" + nodeNumber + ".data");		
				ObjectInputStream o = new ObjectInputStream(f);
				x = ((Double)(o.readObject())).doubleValue();
				y = ((Double)(o.readObject())).doubleValue();
				f.close();
				fixed = true;
			}catch (Exception e){
				x = Math.random();
				y = Math.random();
				fixed = false;
			}
			displayCoords = false;
		}
		
		public Integer GetNodeNumber(){return nodeNumber;}
		public double GetX(){return x;}
		public double GetY(){return y;}
		public boolean GetFixed(){return fixed;}
		public boolean GetDisplayCoords(){return displayCoords;}

		public void SetX(double pX){x=pX;}
		public void SetY(double pY){y=pY;}
		public void SetFixed(boolean pFixed){fixed = pFixed;}
		public void SetDisplayCoords(boolean pDisplayCoords){displayCoords= pDisplayCoords;}
		public void RecordLocation(){
		 	try{
				FileOutputStream f = new FileOutputStream("temp/" + nodeNumber + ".data");			
				ObjectOutputStream o = new ObjectOutputStream(f);
				o.writeObject(new Double(x));
				o.writeObject(new Double(y));
				o.flush();
				f.close();
			}catch (Exception e){
				e.printStackTrace();
			}
				
		}
	}

	public class EdgeInfo
	{
		protected double distance;
		protected Integer sourceNodeNumber;
		protected Integer destinationNodeNumber;
		protected boolean displayLength;//determines if the length should be drawn
		protected boolean is_routing_path;
		
		EdgeInfo(Integer pSource, Integer pDestination)
		{
			sourceNodeNumber = pSource;
			destinationNodeNumber = pDestination; 
			distance = .5;
			is_routing_path = true;
			displayLength = false;
		}
		
		public Integer GetSourceNodeNumber(){return sourceNodeNumber;}
		public Integer GetDestinationNodeNumber(){return destinationNodeNumber;}
		public double GetDistance(){return distance;}
		public void SetDistance(double pDistance){distance = pDistance;}
		public boolean GetDisplayLength(){return displayLength;}
		public void SetDisplayLength(boolean pDisplayLength){displayLength = pDisplayLength;}
		public boolean GetRoutingPath(){
			if(destinationNodeNumber.equals(ObjectMaintainer.getParent(sourceNodeNumber))) return true;
			else if(sourceNodeNumber.equals(ObjectMaintainer.getParent(destinationNodeNumber))) return true;

			return false;
		}
	}
	
	
	public class ProprietaryNodeInfoPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		NodeInfo nodeInfo;
		
		public ProprietaryNodeInfoPanel(NodeInfo pNodeInfo)
		{
			tabTitle = "Location";
			nodeInfo = pNodeInfo;
			//{{INIT_CONTROLS
		setLayout(null);
		Insets ins = getInsets();
		setSize(247,168);
		JLabel3.setText("X Coordinate");
		add(JLabel3);
		JLabel3.setBounds(36,48,84,24);
		JLabel4.setText("Y Coordinate");
		add(JLabel4);
		JLabel4.setBounds(36,72,75,24);
		JTextField1.setNextFocusableComponent(JTextField2);
		JTextField1.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
		JTextField1.setText("1.5");
		add(JTextField1);
		JTextField1.setBounds(120,48,87,18);
		JTextField2.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
		JTextField2.setText("3.2");
		add(JTextField2);
		JTextField2.setBounds(120,72,87,18);
		JCheckBox1.setToolTipText("Check this is you don\'t want the node to move around");
		JCheckBox1.setText("Fixed x/y Coordinates");
		add(JCheckBox1);
		JCheckBox1.setBounds(36,96,168,24);
		JCheckBox2.setToolTipText("Check this is you want the coordinates to be displayed on the screen");
		JCheckBox2.setText("Display x/y Coordinates");
		add(JCheckBox2);
		JCheckBox2.setBounds(36,120,168,24);
			//}}

			//{{REGISTER_LISTENERS
			//}}
		}

		//{{DECLARE_CONTROLS
	javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
	javax.swing.JLabel JLabel4 = new javax.swing.JLabel();
	javax.swing.JTextField JTextField1 = new javax.swing.JTextField();
	javax.swing.JTextField JTextField2 = new javax.swing.JTextField();
	javax.swing.JCheckBox JCheckBox1 = new javax.swing.JCheckBox();
	javax.swing.JCheckBox JCheckBox2 = new javax.swing.JCheckBox();
		//}}

		public void ApplyChanges()
		{
			nodeInfo.SetX(Double.valueOf(JTextField1.getText()).doubleValue());
			nodeInfo.SetY(Double.valueOf(JTextField2.getText()).doubleValue());
			nodeInfo.SetFixed(JCheckBox1.isSelected());
			nodeInfo.SetDisplayCoords(JCheckBox2.isSelected());
		}

		public void InitializeDisplayValues()
		{
			JTextField1.setText(String.valueOf(nodeInfo.GetX()));
			JTextField2.setText(String.valueOf(nodeInfo.GetY()));
			JCheckBox1.setSelected(nodeInfo.GetFixed());
			JCheckBox2.setSelected(nodeInfo.GetDisplayCoords());
		}
	}
	
	public class ProprietaryEdgeInfoPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		EdgeInfo edgeInfo;
		
		public ProprietaryEdgeInfoPanel(EdgeInfo pEdgeInfo)
		{
			tabTitle = "Location";
			edgeInfo = pEdgeInfo;
			//{{INIT_CONTROLS
			setLayout(null);
			Insets ins = getInsets();
			setSize(247,168);
			JLabel3.setText("Distance");
			add(JLabel3);
			JLabel3.setBounds(36,48,84,24);
			JTextField1.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
			JTextField1.setText("1.5");
			add(JTextField1);
			JTextField1.setBounds(120,48,87,18);
			JCheckBox1.setToolTipText("Check this is you want the length of the edge to be displayed");
			JCheckBox1.setText("Display Length");
			add(JCheckBox1);
			JCheckBox1.setBounds(36,66,168,24);
			//}}

			//{{REGISTER_LISTENERS
			//}}
		}

		//{{DECLARE_CONTROLS
		javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
		javax.swing.JTextField JTextField1 = new javax.swing.JTextField();
		javax.swing.JCheckBox JCheckBox1 = new javax.swing.JCheckBox();
		//}}

		public void ApplyChanges()
		{
			edgeInfo.SetDistance(Double.parseDouble(JTextField1.getText()));
			edgeInfo.SetDisplayLength(JCheckBox1.isSelected());
		}

		public void InitializeDisplayValues()
		{
			JTextField1.setText(String.valueOf(edgeInfo.GetDistance()));
			JCheckBox1.setSelected(edgeInfo.GetDisplayLength());
		}

	}

void drawLine(Graphics g,
              int x1, int y1,
              int x2, int y2,
              int lineWidth) {
    if (lineWidth == 1)
      g.drawLine(x1, y1, x2, y2);
    else {
      double angle;
      double halfWidth = ((double)lineWidth)/2.0;
      double deltaX = (double)(x2 - x1);
      double deltaY = (double)(y2 - y1);
      if (x1 == x2)
        angle=Math.PI;
      else
        angle=Math.atan(deltaY/deltaX)+Math.PI/2;
      int xOffset = (int)(halfWidth*Math.cos(angle));
      int yOffset = (int)(halfWidth*Math.sin(angle));
      int[] xCorners = { x1-xOffset, x2-xOffset+1,
                         x2+xOffset+1, x1+xOffset };
      int[] yCorners = { y1-yOffset, y2-yOffset,
                         y2+yOffset+1, y1+yOffset+1 };
      g.fillPolygon(xCorners, yCorners, 4);
    }
}
}
