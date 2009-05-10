// $Id: SensorAnalyzer.java,v 1.3 2003/10/07 21:46:08 idgay Exp $

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

//*********************************************************
//*********************************************************
//This file is a template that shows the conventions on how to write a 
//PacketAnalyzer subclass.  It shows you how to do the following things
// 1. recieve and process a new data packet
// 2. recieve and process new node or edge clicks in the interface 
// 3. recieve and process the creation or deletion of nodes or edges
// 4. Display a panel on the edge or node properties panels when they are clicked
// 5. Add graphical output to the node, edge or the screen
// 6. Display a properties panel to edit parameters of this PacketAnalyzer
// 7. run this process in the background as a seperate thread
//*********************************************************
//*********************************************************
//If you want to write a new class to do packet analysis, you should
//not change any files besides this one, the MainFrame class (where you add menus)
//And the MainClass (where this class is instantiated).  This modularity
//will help maintain future compatibilty with other people's analyzers.
//*********************************************************
//*********************************************************
//The main thing to understand here is that the class is highly multithreaded.
// 1.  It can spawn a thread in the constructor to run in the background (as shown below)
// 2.  It can spawn new threads every time an event is recieved (to free the eventGenerating thread)
// 3.  Every "EventRecieved()" function is initially run on the thread of the object that generated the event
//        In this case, the following functions are initially run on the threads of the following objects
//          a.  PacketRecieved()                             -->  PacketListener
//          b.  NodeCreated/Deleted(), EdgeCreated/Deleted() -->  ObjectMaintainer
//			c.  NodeClicked(), EdgeClicked()				 -->  DisplayManager
//			d.	PaintNode(), PaintEdge(), PaintScreen()		 -->  DisplayManager
//			e.  GetProrietaryNode/EdgeDisplayPanel()		 --> DisplayManager
// 4.  All Get/Set functions may be called by the GUI thread
// 5.  The constructor is called on the main() thread of the entire program
//*********************************************************
//*********************************************************
//As a general rule for avoiding synchronization problems:
// 1.  All functions should be synchronized (except run() and the constructor) to eliminate problems with member 
//      variables (i.e. only one thread can be running functions of this object at a time)
// 2.  All threads in the constructor should be started at the end of the constructor to eliminate problems between that thread and the code in the constructor
// 3.  Be careful about synchronizing over methods that call functions in other classes
//		It could cause problems if, for example, I grab resource A, somebody else grabs resource B, I grab resource B, somebody else wants resource A.  We both end up waiting forever. 
// 4.  Try not to call more than one synchronized method within the same call stack. (don't have one thread synchronized on more than one object at a time)
//*********************************************************
//*********************************************************

package net.tinyos.tinydb.topology.PacketAnalyzer;//make sure you put this class in the net.tinyos.tinydb.topology/PacketAnalyzer folder

import net.tinyos.tinydb.topology.*;
import net.tinyos.tinydb.topology.event.*;
import net.tinyos.tinydb.topology.util.*;
import java.util.*;
import java.lang.*;
import javax.swing.*;
import net.tinyos.tinydb.topology.Dialog.*;
import net.tinyos.tinydb.topology.Packet.*;
import java.awt.*;

        
public class SensorAnalyzer extends PacketAnalyzer //implements java.lang.Runnable 
{
	          //Define your member variables (try not to have publics)
	protected static Hashtable proprietaryNodeInfo;
	protected static TwoKeyHashtable proprietaryEdgeInfo;
//	protected static Thread thread;

              //------------------------------------------------------------------------
	          //*****---CONSTRUCTOR---******// 
	          //the constructor should be called by the MainClass constructor when 
	          //it instantiates all the packetAnalyzers that we want
	          //Make sure you edit that constructor to do so
	public SensorAnalyzer()
	{
        //initialize your variables

		//create new hashtables for your proprietary data
		proprietaryNodeInfo = new Hashtable();
		proprietaryEdgeInfo = new TwoKeyHashtable();
				      
        //register to be notified of nodes and edges being created or deleted
		MainClass.objectMaintainer.AddEdgeEventListener(this);//listen to node events
		MainClass.objectMaintainer.AddNodeEventListener(this);//listen to edge event
		AnalyzerDisplayEnable();
	}
              //------------------------------------------------------------------------
              //EXAMPLE FUNCTION
	          //*****---An example function with example code---******//
	          //naming convention is as shown here.
	          //Be sure to synchronize this function if it is being called from more than
	          //one of the following threads
	          // 1.  your own thread (the run() function)
	          // 2.  PacketReciever threads (packetRecieved() function)
	          // 3.  ObjectMaintainer thread (NodeCreated/Deleted() or EdgeCreated/Deleted() functions)
	          // 4.  GUI thread (Node/Edge Clicked(), GetNode/EdgePanel(), PaintNode/Edge/Screen() functions)
	          // 5.  Any Get/Set function or other function called by the GUI thread
	          //If you do not want to synchronize the entire method (or any method in this class), 
	          //you have to figure out which parts may need to be synchronized over which 
	          //variables, and do it manually
/*	public synchronized void DummyFunction(Integer pNodeNumber)
	{
		NodeInfo currentNodeInfo;

		//Always synchronize over MainClass.nodes or MainClass.edges if you care that somebody else might add or delete nodes/edges
		if(proprietaryNodeInfo.contains(pNodeNumber)==true)             //e.g the node exists for the if() statement but is deleted and you get a null pointer exception when you try to paint it (In this case you should just use: currentNode = MainClass.nodes.get(Number) and afterward check if currentNode == null.  Remember to synchronize over currentNode).
		{
			currentNodeInfo = ((NodeInfo)proprietaryNodeInfo.get(pNodeNumber));	    	
		}
		else 
		{
			currentNodeInfo = new NodeInfo(pNodeNumber);
		}
	}*/
			  //*****---An example function with example code---******//
              //------------------------------------------------------------------------
	 
	          
              //------------------------------------------------------------------------
	          //*****---Packet Recieved event handler---******//
	          //this function will be called by the thread running the packetReciever
	          //everytime a new packet is recieved
	          //make sure it is synchronized if it modifies any of your data
    public synchronized void PacketReceived(PacketEvent e)
    {
                //this function defines what you do when a new packet is heard by the system (recall that the parent class (PacketAnalyzer) already registered you to listen for new packets automatically)
                //if this is a long function, you should call it in a seperate thread to allow the PacketReciever thread to continue recieving packets
                        
    	Packet packet = e.GetPacket();
    	Vector node_list = packet.CreateRoutePathArray();
	for(int i = 0; i < node_list.size() - 1; i ++){
    		Integer currentNodeNumber = (Integer)node_list.elementAt(i);
    		NodeInfo currentNodeInfo;   
    		if( (currentNodeInfo = (NodeInfo)proprietaryNodeInfo.get(currentNodeNumber)) != null) {
    			currentNodeInfo.SetValue(packet.getValue());
    		}
	}
    }	
	          //It is called by net.tinyos.tinydb.topology.PacketAnalyzer.ObjectMainter
    public synchronized void NodeCreated(NodeEvent e)
    {
    	Integer newNodeNumber = e.GetNodeNumber();//you probably want to create a new info pbject to track the data of this new node
    	proprietaryNodeInfo.put(newNodeNumber, new NodeInfo(newNodeNumber));
    }
	          //*****---Node Created---******//
              //------------------------------------------------------------------------

    
              //------------------------------------------------------------------------
    	          //*****---Node Deleted---******//
	          //this function defines what you do when a new node is deleted
	          //It is called by net.tinyos.tinydb.topology.PacketAnalyzer.ObjectMainter
    public synchronized void NodeDeleted(NodeEvent e)
    {
    	Integer deletedNodeNumber = e.GetNodeNumber();//you probably want to delete the info pbject to track the data of this new node
    	proprietaryNodeInfo.remove(deletedNodeNumber);
    }
	          //*****---Node Deleted---******//
              //------------------------------------------------------------------------


              //------------------------------------------------------------------------
	          //*****---Edge Created---******//
	          //this function defines what you do when a new edge is created
	          //It is called by net.tinyos.tinydb.topology.PacketAnalyzer.ObjectMainter
/*    public synchronized void EdgeCreated(EdgeEvent e)
    {
    	Integer sourceNodeNumber = e.GetSourceNodeNumber();
    	Integer destinationNodeNumber = e.GetDestinationNodeNumber();//you probably want to create a new info pbject to track the data of this new node
    	proprietaryEdgeInfo.put(sourceNodeNumber, destinationNodeNumber, new EdgeInfo(sourceNodeNumber, destinationNodeNumber));
    }*/
	          //*****---Edge Created---******//
              //------------------------------------------------------------------------


              //------------------------------------------------------------------------
	          //*****---Edge Deleted---******//
	          //this function defines what you do when a new edge is deleted
	          //It is called by net.tinyos.tinydb.topology.PacketAnalyzer.ObjectMainter
/*    public synchronized void EdgeDeleted(EdgeEvent e)
    {
    	Integer sourceNodeNumber = e.GetSourceNodeNumber();
    	Integer destinationNodeNumber = e.GetDestinationNodeNumber();//you probably want to create a new info pbject to track the data of this new node
    	proprietaryEdgeInfo.remove(sourceNodeNumber, destinationNodeNumber);
    }*/
	          //*****---EdgeDeleted---******//
              //------------------------------------------------------------------------


              //************************************************************************
              //************************************************************************
              //the following two functions correspond to the 
              //NodeClickedEventListener, EdgeClickedEventListener interfaces and will
              //only work if you register as a listener for these events
              //************************************************************************
              //************************************************************************

              
              //------------------------------------------------------------------------
	          //*****---Node Clicked---******//
	          //this function defines what you do when a node is clicked
	          //It is called by net.tinyos.tinydb.topology.DisplayManager
/*    public synchronized void NodeClicked(NodeClickedEvent e)
    {
    	Integer nodeClicked = e.GetNodeNumber();
    	      //and maybe do some other processing
    }*/
	          //*****---Node Clicked---******//
              //------------------------------------------------------------------------

	          
              //------------------------------------------------------------------------
	          //*****---Edge Clicked---******//
	          //this function defines what you do when an edge is clicked
	          //It is called by net.tinyos.tinydb.topology.DisplayManager
/*    public synchronized void EdgeClicked(EdgeClickedEvent e)
    {
		Integer sourceClicked = e.GetSourceNodeNumber();    	      
		Integer destinationClicked = e.GetDestinationNodeNumber();    	      
    	      //and maybe do some other processing
    }*/
	          //*****---Edge Clicked---******//
              //------------------------------------------------------------------------
    
    
    
    
    
              //************************************************************************
              //************************************************************************
              //the following two functions correspond to the 
              //NodeDialogContributor, EdgeDialogContributor interfaces and will
              //only work if you register as a contributor as shown in the constructor.
              //You must define the ProprietaryNodeInfoPanel and ProprietaryEdgeInfoPanel
              //classes and they will automaticallyshow up when a node/edge is clicked
              //by using the following two functions.
              //************************************************************************
              //************************************************************************

    
              //------------------------------------------------------------------------
	          //GET PROPRIETARY NODE INFO PANEL
	          //This function returns the Panel that you define it to retunr
	          //which will then automatically appear ina dialog when a node is clicked.
	          //this function is called by DisplayManager
	public ActivePanel GetProprietaryNodeInfoPanel(Integer pNodeNumber)
	{
		NodeInfo nodeInfo = (NodeInfo)proprietaryNodeInfo.get(pNodeNumber);
		if(nodeInfo==null) 
			return null;
		ProprietaryNodeInfoPanel panel = new ProprietaryNodeInfoPanel(nodeInfo);
		return (ActivePanel)panel;
	}
	          //GET PROPRIETARY NODE INFO PANEL
              //------------------------------------------------------------------------


              //------------------------------------------------------------------------
	          //GET PROPRIETARY EDGE INFO PANEL
	          //This function returns the Panel that you define it to retunr
	          //which will then automatically appear ina dialog when an edge is clicked.
	          //this function is called by DisplayManager
/*	public ActivePanel GetProprietaryEdgeInfoPanel(Integer pSourceNodeNumber, Integer pDestinationNodeNumber) 
	{
		EdgeInfo edgeInfo = (EdgeInfo)proprietaryEdgeInfo.get(pSourceNodeNumber, pDestinationNodeNumber);
		if(edgeInfo==null)
			return null;
		ProprietaryEdgeInfoPanel panel = new ProprietaryEdgeInfoPanel(edgeInfo);
		return (ActivePanel)panel;
	}*/
	          //GET PROPRIETARY EDGE INFO PANEL
              //------------------------------------------------------------------------


    
    
    
    
              //************************************************************************
              //************************************************************************
              //the following three functions correspond to the 
              //NodePainter, EdgePainter, and ScreenPainter interfaces and will
              //only work if you register as a Painter as shown in the constructor.
              //Whatever  painting function you implement here will be called every
              //time a node or edge is painted, and after all the nodes/edges are painted
              //the paintScreen functions are called.  You are called in the order that
              //you register as a painter.
              //************************************************************************
              //************************************************************************

              
              //------------------------------------------------------------------------
	          //NODE PAINTER
	          //Put some function here to paint whatever you want over the node.
	          //The x1,y1 coordinates are the top left corner within which the node will be drawn
	          //The x2,y2 coordinates are the bottom right corner
	          //Paint everything on the graphics object
	          //this function is called by DisplayManager
	public void PaintNode(Integer pNodeNumber, int x1, int y1, int x2, int y2, Graphics g) 
	{
		NodeInfo nodeInfo = (NodeInfo)proprietaryNodeInfo.get(pNodeNumber);
		if(nodeInfo==null) return;
		int light = nodeInfo.GetValue();
		if(light == -1) return;
		nodeInfo.centerX = (x1 + x2)/2;
		nodeInfo.centerY = (y1 + y2)/2;
		//System.out.println(pNodeNumber);
	}
	          //NODE PAINTER
              //------------------------------------------------------------------------
              
              
              
              //------------------------------------------------------------------------
	          //SCREEN PAINTER
	          //Put some function here to paint whatever you want over the screen before and after
	          //all edges and nodes have been painted.
	public void PaintScreenBefore(Graphics g) 
	{

		Dimension d = MainClass.mainFrame.GetGraphDisplayPanel().getSize();
		NodeInfo nodeInfo;
		int x = 0;
		int y = 0;
		int step = 10;	

		for(;x < d.width; x += step){
			for(y = 0;y < d.height; y += step){
				double val = 0;
				double sum = 0;
				double total = 0;
				double min = 10000000;
				for(Enumeration nodes = proprietaryNodeInfo.elements();nodes.hasMoreElements();){
					nodeInfo = (NodeInfo) nodes.nextElement();
					double dist = distance(x, y, nodeInfo.centerX, nodeInfo.centerY);	
					if(nodeInfo.value != -1){ 
						if(dist < min) min = dist;
						val += ((double)nodeInfo.value)  / dist /dist;
						sum += (1/dist/dist);
					}
				}
				int reading = (int)(val / sum);
				reading = reading >> 2;
				if (reading > 255)
					reading = 255;
				g.setColor(new Color(reading, reading, reading));
				g.fillRect(x, y, step, step);
			}
		}
	}
	public double distance(int x, int y, int x1, int y1){
		return Math.sqrt( (x-x1)*(x-x1)+(y-y1)*(y-y1));
	}
	public void PaintScreenAfter(Graphics g) {
		      //paint something on the graphics object
	}
	          //SCREEN PAINTER
              //------------------------------------------------------------------------


              
              //************************************************************************
              //************************************************************************
              //the following functions correspond to the thread instantiated in the
              //constructor and will only work if you actually instantiate it.
              //The Run function is what the thread does.  The functions following
              //it are wrappers of the thread function to let us control the thread.
              //************************************************************************
              //************************************************************************
         
              
              //------------------------------------------------------------------------
	          //*****---Run---******//
              //this function runs in a seperate thread whenever you call the two lines: 
              //   thread = new Thread(this); 
              //   thread.start();
/*    public void run()
    {
		while(true)
    	{
    		//do something here which will run in the background
    		//then sleep for a while
    		try
			{
	    			thread.sleep(1000);//time is in milliseconds
	    	}
			catch(Exception e){e.printStackTrace();}
		}
		
    }*/
	          //*****---Run---******//
              //------------------------------------------------------------------------
    

              //------------------------------------------------------------------------
	          //*****---Thread commands---******//
	          //you might want to add these thread commands 
/*    public void start(){ try{ thread=new Thread(this);thread.start();} catch(Exception e){e.printStackTrace();}}
    public void stop(){ try{ thread.stop();} catch(Exception e){e.printStackTrace();}}
    public void sleep(long p){ try{ thread.sleep(p);} catch(Exception e){e.printStackTrace();}}
    public void setPriority(int p) { try{thread.setPriority(p);} catch(Exception e){e.printStackTrace();}}    */
			//*****---Thread commands---******//
              //------------------------------------------------------------------------

              //------------------------------------------------------------------------
              //INTERFACE TO PROPRIETARY DATA
              //write some functions here that will let other Analyzers find and user your data
	public NodeInfo GetNodeInfo(Integer nodeNumber){return (NodeInfo)proprietaryNodeInfo.get(nodeNumber);}
//	public EdgeInfo GetEdgeInfo(Integer sourceNumber, Integer destinationNumber){return (EdgeInfo)proprietaryEdgeInfo.get(sourceNumber,destinationNumber);}
	public Enumeration GetNodeInfo(){return proprietaryNodeInfo.elements();}
//	public Enumeration GetEdgeInfo(){return proprietaryEdgeInfo.elements();}
              //INTERFACE TO PROPRIETARY DATA
              //------------------------------------------------------------------------




              //------------------------------------------------------------------------
	          //*****---GET/SET COMMANDS---******//
//	public synchronized int GetVariableName(){ return variableName;}
//	public synchronized void SetVariableName(int pVariableName){variableName = pVariableName;}
			  //*****---GET/SET COMMANDS---******//
              //------------------------------------------------------------------------




              //------------------------------------------------------------------------
	          //*****---SHOW PROPERTIES DIALOG---******//
	          //this function can be called by MainFrame (by the menus, in particular)
	          //and should simply show the dialog as shown here.
	          //You need to define the class "PacketAnalyzerTemplatePropertiesPanel"
	          //in order for this to do anything.  it is useful for setting parameters
	          //on your analyzer.
	public void ShowPropertiesDialog() 
	{
		StandardDialog newDialog = new StandardDialog(new DisplayPropertiesPanel(this));
		newDialog.show();
	}
			  //*****---SHOW PROPERTIES DIALOG---******//
              //------------------------------------------------------------------------





	        //*********************************************************
	        //*********************************************************
	        //*********************************************************
              //NODE INFO CLASS
              //this class should hold any special information you hold about the
              //node, for example time created or a history of the number of packets
              //forwarded through this mote or whetever it is you are studying
	public class NodeInfo
	{
		protected Integer nodeNumber;
		protected int value;
		protected int centerY;
		protected int centerX;
		
		public NodeInfo(Integer pNodeNumber)
		{
			nodeNumber = pNodeNumber;
			value = -1;//if it doesn't change from this value nothing will be written
		}
		
		public Integer GetNodeNumber()
		{
			return nodeNumber;
		}
		
		public void SetNodeNumber(Integer pNodeNumber)
		{
			nodeNumber = pNodeNumber;
		}
		
		public int GetValue(){return value;}
		public void SetValue(int l){value = l;}
	}                                         
	          //NODE INFO
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************
	
	
	
	        
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************
	          //EDGEINFO
              //this class should hold any special information you hold about the
              //edge, for example time created or a history of the number of packets
              //forwarded over this edge or whetever it is you are studying
/*	public class EdgeInfo
	{
		protected Integer sourceNodeNumber;
		protected Integer destinationNodeNumber;
		
		public EdgeInfo(Integer pSourceNodeNumber, Integer pDestinationNodeNumber)
		{
			sourceNodeNumber = pSourceNodeNumber;
			destinationNodeNumber = pDestinationNodeNumber;
		}
		
		public Integer GetSourceNodeNumber()
		{
			return sourceNodeNumber;
		}
		
		public void SetSourceNodeNumber(Integer pNodeNumber)
		{
			sourceNodeNumber = pNodeNumber;
		}
	}*/
	          //EDGE INFO
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************



	        //*********************************************************
	        //*********************************************************
	        //*********************************************************
              //PROPRIETARY NODE INFO DISPLAY PANEL
              //This class is an ActivePanel and should have all the information
              //in GUI form that this class stores with respect to nodes
              //It should be returned with GetProprietaryNodeInfoPanel and it will be displayed
              //with all the other packet analyzer proprietary info when a node is clicked.
	public class ProprietaryNodeInfoPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		NodeInfo nodeInfo;
		
		public ProprietaryNodeInfoPanel(NodeInfo pNodeInfo)
		{
			nodeInfo = pNodeInfo;
			tabTitle = "Sensor Value";//this will be the title of the tab
			//{{INIT_CONTROLS
			setLayout(null);
//			Insets ins = getInsets();
			setSize(307,168);
			JLabel3.setToolTipText("This text will appear with mouse hover over this component");
			JLabel3.setText("Node Number:");
			add(JLabel3);
			JLabel3.setBounds(12,36,108,24);
			JLabel4.setToolTipText("This is the value of NodeNumber");
			JLabel4.setText("text");
			add(JLabel4);
			JLabel4.setBounds(12,60,108,24);
			JLabel5.setToolTipText("This text will appear with mouse hover over this component");
			JLabel5.setText("Sensor Reading:");
			add(JLabel5);
			JLabel5.setBounds(12,84,108,24);
			JLabel6.setToolTipText("This is the value of Sensor Reading");
			JLabel6.setText("text");
			add(JLabel6);
			JLabel6.setBounds(12,108,108,24);
			//}}

			//{{REGISTER_LISTENERS
			//}}
		}

		//{{DECLARE_CONTROLS
		javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel4 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel5 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel6 = new javax.swing.JLabel();
		//}}
		
		public void ApplyChanges()//this function will be called when the apply button is hit
		{
			nodeInfo.SetNodeNumber(Integer.getInteger(JLabel4.getText()));
		}
		
		public void InitializeDisplayValues()//this function will be called when the panel is first shown
		{
			JLabel4.setText(String.valueOf(nodeInfo.GetNodeNumber()));
			JLabel6.setText(String.valueOf(nodeInfo.GetValue()));
		}
	}	          
              //PROPRIETARY NODE INFO DISPLAY PANEL
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************


	        //*********************************************************
	        //*********************************************************
	        //*********************************************************
              //PROPRIETARY EDGE INFO DISPLAY PANEL
              //This class is an ActivePanel and should have all the information
              //in GUI form that this class stores with respect to EDGES
              //It should be return with GetProprietaryEdgeInfoPanel and it will be displayed
              //with all the other packet analyzer proprietary info when a edgeis clicked.
/*	public class ProprietaryEdgeInfoPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		EdgeInfo edgeInfo;
		
		public ProprietaryEdgeInfoPanel(EdgeInfo pEdgeInfo)
		{
			edgeInfo = pEdgeInfo;
			tabTitle = "Light";//this will be the title of the tab
			//{{INIT_CONTROLS
			setLayout(null);
//			Insets ins = getInsets();
			setSize(307,168);
			JLabel3.setToolTipText("This text will appear with mouse hover over this component");
			JLabel3.setText("Source Node NUmber:");
			add(JLabel3);
			JLabel3.setBounds(12,36,108,24);
			JLabel4.setToolTipText("This is the value of SOURCENodeNumber");
			JLabel4.setText("text");
			add(JLabel4);
			JLabel4.setBounds(12,60,108,24);
			//}}

			//{{REGISTER_LISTENERS
			//}}
		}

		//{{DECLARE_CONTROLS
		javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel4 = new javax.swing.JLabel();
		//}}
		
		public void ApplyChanges()//this function will be called when the apply button is hit
		{
			edgeInfo.SetSourceNodeNumber(Integer.getInteger(JLabel4.getText()));
		}
		
		public void InitializeDisplayValues()//this function will be called when the panel is first shown
		{
			JLabel4.setText(String.valueOf(edgeInfo .GetSourceNodeNumber()));
		}
	}*/	          
              //PROPRIETARY NODE INFO DISPLAY PANEL
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************


	        
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************
              //PacketAnalyzerTemplatePropertiesPanel
              //This class is an ActivePanel and should have all the information
              //in GUI form that this class stores with respect to EDGES
              //It will be displayed automatically with ShowPropertiesDialog
	public class DisplayPropertiesPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		SensorAnalyzer analyzer;
		
		public DisplayPropertiesPanel(SensorAnalyzer pAnalyzer)
		{
			analyzer = pAnalyzer;
			tabTitle = "Light";//this will be the title of the tab
			//{{INIT_CONTROLS
			setLayout(null);
//			Insets ins = getInsets();
			setSize(307,168);
			JLabel3.setToolTipText("This text will appear with mouse hover over this component");
			JLabel3.setText("Variable Name:");
			add(JLabel3);
			JLabel3.setBounds(12,36,108,24);
			JLabel4.setToolTipText("This is the value of Variable Name");
			JLabel4.setText("text");
			add(JLabel4);
			JLabel4.setBounds(12,60,108,24);
			//}}

			//{{REGISTER_LISTENERS
			//}}
		}

		//{{DECLARE_CONTROLS
		javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel4 = new javax.swing.JLabel();
		//}}
		
		public void ApplyChanges()//this function will be called when the apply button is hit
		{
//			analyzer.SetVariableName(Integer.getInteger(JLabel4.getText()).intValue());
		}
		
		public void InitializeDisplayValues()//this function will be called when the panel is first shown
		{
//			JLabel4.setText(String.valueOf(analyzer.GetVariableName()));
		}
	}	          
              //PacketAnalyzerTemplatePropertiesPanel
	        //*********************************************************
	        //*********************************************************
	        //*********************************************************

}
