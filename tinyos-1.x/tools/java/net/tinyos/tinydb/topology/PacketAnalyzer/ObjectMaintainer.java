// $Id: ObjectMaintainer.java,v 1.2 2003/10/07 21:46:08 idgay Exp $

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

//**************************************************************************
//**************************************************************************
//this class reads packets and updates all nodes and paths
//that are in each packet with timestamps, creating
//those nodes or paths that do not exist.
//It also runs the "run" method as a seperate thread,
//which constantly checks the nodes and paths for having expired.
//**************************************************************************
//**************************************************************************

package net.tinyos.tinydb.topology.PacketAnalyzer;

import net.tinyos.tinydb.topology.*;
import net.tinyos.tinydb.topology.event.*;
import net.tinyos.tinydb.topology.util.*;
import java.util.*;
import java.lang.*;
import java.io.*;
import java.awt.*;
import javax.swing.*;
import net.tinyos.tinydb.topology.Dialog.*;
import net.tinyos.tinydb.topology.Packet.*;

 
public class ObjectMaintainer extends PacketAnalyzer implements Runnable
{
	          //these variables define when to eliminate nodes that are no longer in the network
	protected static long nodeExpireTime;
	protected static long edgeExpireTime;
	protected static long nodeInitialPersistance;
	protected static long edgeInitialPersistance;
	protected static long nodeInitialDormancy;
	protected static long edgeInitialDormancy;
//	protected static long edgeStability;
	//protected static long networkSpeed;
	protected static long expirationCheckRate;
	public static Hashtable nodeInfo;
	public static TwoKeyHashtable edgeInfo;
	protected static Thread oldObjectDeleterThread;
	protected static Vector nodeListeners;
	protected static Vector edgeListeners;

	public ObjectMaintainer()
	{
				//register myself to recieve NodeClickedEvents and EdgeClickedEvents
		// MainClass.displayManager.AddNodeDialogContributor(this);
		MainClass.displayManager.AddEdgeDialogContributor(this);
		
		      //all values are in milliseconds
		nodeExpireTime = 50000;
		edgeExpireTime = 20000;
		nodeInitialPersistance = 2500;
		edgeInitialPersistance = 2500;
		nodeInitialDormancy = 7500;
		edgeInitialDormancy = 2500;
		expirationCheckRate = 1500;//in milliseconds
		
		nodeInfo = new Hashtable();
		edgeInfo = new TwoKeyHashtable();
		nodeListeners = new Vector();
		edgeListeners = new Vector();
		oldObjectDeleterThread = new Thread(this);
		try{
			oldObjectDeleterThread.setPriority(Thread.MIN_PRIORITY);
			oldObjectDeleterThread.start(); //recall that start() calls the run() method defined in this class
		}
		catch(Exception e){e.printStackTrace();}

	}
              //-----------------------------------------------------------------------
	          //*****---Packet Recieved event handler---******//
    	      //when a new packet is recieved
    	      //look at the list and order of nodes in the hop-path
    	      //update the node times, create nodes that do not exist
    	      //update the edge times, create edges that do not exist
    public  void PacketReceived(PacketEvent e)
    {
    	Integer currentNodeNumber;
    	Integer previousNodeNumber=new Integer(-1);
    	NodeInfo currentNodeInfo;
    	NodeInfo previousNodeInfo=null;
    	EdgeInfo currentEdgeInfo;
    	Packet packet = e.GetPacket();

		Date eventTime = e.GetTime();
		Vector routePath = packet.CreateRoutePathArray();//vector of "Integer" objects
		
    	      //look at the list and order of nodes in the hop-path
		for(int count=0; count < routePath.size(); count++)
		{
			currentNodeNumber = (Integer)routePath.elementAt(count);
			// System.out.println("checking: " + currentNodeNumber);
			if((currentNodeInfo = (NodeInfo)nodeInfo.get(currentNodeNumber)) !=null){
				//System.out.println(currentNodeInfo.GetCreated());
				//System.out.println(NodeHasBeenSeenRecently(currentNodeInfo.GetTimeLastSeen(), eventTime));
				if( (currentNodeInfo.GetCreated()==false) && NodeHasBeenSeenRecently(currentNodeInfo.GetTimeLastSeen(), eventTime)){
					currentNodeInfo.SetCreated(true);
					currentNodeInfo.SetTimeLastSeen(eventTime);
					TriggerNodeCreatedEvent(new NodeEvent(this, currentNodeNumber, Calendar.getInstance().getTime()));	
                		} else {
                			currentNodeInfo.SetTimeLastSeen(eventTime);
				}
            		} else {
				//System.out.println("added: " + currentNodeNumber);
				currentNodeInfo = new NodeInfo(currentNodeNumber, eventTime);
				nodeInfo.put(currentNodeNumber, currentNodeInfo);

				currentNodeInfo.SetCreated(true);
				TriggerNodeCreatedEvent(new NodeEvent(this, currentNodeNumber, Calendar.getInstance().getTime()));
				 
            		}

			if(count != 0) {
				if( (currentEdgeInfo = (EdgeInfo)edgeInfo.get(currentNodeNumber,previousNodeNumber)) != null) {
					currentEdgeInfo.SetTimeLastSeen(eventTime);
				} else if((currentNodeInfo!=null) && (previousNodeInfo!=null)&&(currentNodeInfo.GetCreated() && previousNodeInfo.GetCreated())) {
					edgeInfo.put(previousNodeNumber, currentNodeNumber, new EdgeInfo(previousNodeNumber, currentNodeNumber, eventTime));
					TriggerEdgeCreatedEvent(new EdgeEvent(this, previousNodeNumber, currentNodeNumber, Calendar.getInstance().getTime()));
				}
				if(previousNodeInfo != null) previousNodeInfo.SetParent(currentNodeNumber);
			}
			previousNodeNumber = currentNodeNumber;
			previousNodeInfo = currentNodeInfo;
		}     //end for loop through hop-list
	}
	
	static Integer getParent(Integer pNode){
			NodeInfo currentNodeInfo = (NodeInfo)nodeInfo.get(pNode);
			if(currentNodeInfo == null) return new Integer(-1);
			else return currentNodeInfo.GetParent();
	}
					
	          //*****---Packet Recieved event handler---******//
	public static boolean isBase(Integer pNode) {
		return pNode.intValue() == 0;
	}
					
	  //this function constantly deletes old nodes and edges
    public void run()
    {
		while(true)
    	{
    		EliminateExpiredNodes();
    		EliminateExpiredEdges();
			try
			{
	    		oldObjectDeleterThread.sleep(expirationCheckRate);
	    	}
			catch(Exception e){e.printStackTrace();}
		}
		
    }

  //*****---NodeHasBeenSeenRecently---******//
    public boolean NodeHasBeenSeenRecently(Date TimeLastSeen, Date currentTime)
    {
		if((currentTime.getTime() - nodeInitialDormancy)  <= TimeLastSeen.getTime())//if it has been seen in time less than nodeInitialDormancy
		{
			return true;
		}
		return false;
    }

	  //*****---Eliminiate Nodes---******//
     void EliminateExpiredNodes()
    {
		Integer currentNodeNumber;
		NodeInfo currentNodeInfo;
		
		      //for all nodes in the network
		long currentTime;
		for(Enumeration nodes = nodeInfo.elements();nodes.hasMoreElements();) 
		{
			currentNodeInfo = (NodeInfo)nodes.nextElement();
			currentNodeNumber = currentNodeInfo.GetNodeNumber();
			if(currentNodeNumber.intValue() != 0){;
			
				 //if node has expired, eliminate it
				currentTime = Calendar.getInstance().getTime().getTime();//milliseconds since January 1, 1970
				if( (currentTime - currentNodeInfo.GetTimeLastSeen().getTime() > nodeExpireTime) &&
					(currentTime - currentNodeInfo.GetTimeCreated().getTime() > nodeInitialPersistance))
				{
					nodeInfo.remove(currentNodeNumber);
					TriggerNodeDeletedEvent(new NodeEvent(this, currentNodeNumber, Calendar.getInstance().getTime()));
				}
			}
		}
    }
    
     void EliminateExpiredEdges()
    {
		
		Integer sourceNumber;
		Integer destinationNumber;
		Integer currentEdgeNumber;
		EdgeInfo currentEdgeInfo;
		
		      //for all edges in the network
		long currentTime; 
		for(Enumeration edges = edgeInfo.elements();edges.hasMoreElements();) 
		{
			currentEdgeInfo = (EdgeInfo)edges.nextElement();
			sourceNumber = currentEdgeInfo.GetSourceNodeNumber();//final vairables that don't need to be synchronized
			destinationNumber = currentEdgeInfo.GetDestinationNodeNumber();//final vairables that don't need to be synchronized

						 //if edge has expired, eliminate it
			currentTime = Calendar.getInstance().getTime().getTime();//milliseconds since January 1, 1970
			if( (currentTime - currentEdgeInfo.GetTimeLastSeen().getTime() > edgeExpireTime) &&
				(currentTime - currentEdgeInfo.GetTimeCreated().getTime() > edgeInitialPersistance) )
			{
				edgeInfo.remove(sourceNumber, destinationNumber);
				TriggerEdgeDeletedEvent(new EdgeEvent(this, sourceNumber, destinationNumber, Calendar.getInstance().getTime()));
			}
		}
    }
    
	          //*****---ADD EVENT LISTENER---******//
	public static void AddNodeEventListener(NodeEventListener pListener)
	{
		nodeListeners.add(pListener);
	}
	
	public static void RemoveNodeEventListener(NodeEventListener pListener)
	{
		nodeListeners.remove(pListener);
	}
	
	public static void AddEdgeEventListener(EdgeEventListener pListener)
	{
		edgeListeners.add(pListener);
	}

	public static void RemoveEdgeEventListener(EdgeEventListener pListener)
	{
		edgeListeners.remove(pListener);
	}
	          //*****---TRIGGER EVENTS---******//
	protected void TriggerNodeCreatedEvent(NodeEvent e)
	{
		      //for each listener
		NodeEventListener currentListener;
		for(Enumeration list = nodeListeners.elements(); list.hasMoreElements();)
		{
			currentListener = (NodeEventListener)list.nextElement();
			currentListener.NodeCreated(e);//send the listener an event
        }			
	}

	protected void TriggerNodeDeletedEvent(NodeEvent e)
	{
		      //for each listener
		NodeEventListener currentListener;
		for(Enumeration list = nodeListeners.elements(); list.hasMoreElements();)
		{
			currentListener = (NodeEventListener)list.nextElement();
			currentListener.NodeDeleted(e);//send the listener an event
        }			
	}

	protected void TriggerEdgeCreatedEvent(EdgeEvent e)
	{
		      //for each listener
		EdgeEventListener currentListener;
		for(Enumeration list = edgeListeners.elements(); list.hasMoreElements();)
		{
			currentListener = (EdgeEventListener)list.nextElement();
			currentListener.EdgeCreated(e);//send the listener an event
        }			
	}

	protected void TriggerEdgeDeletedEvent(EdgeEvent e)
	{
		      //for each listener
		EdgeEventListener currentListener;
		for(Enumeration list = edgeListeners.elements(); list.hasMoreElements();)
		{
			currentListener = (EdgeEventListener)list.nextElement();
			currentListener.EdgeDeleted(e);//send the listener an event
        }			
	}

	          //*****---SHOW PROPERTIES DIALOG---******//
	public void ShowPropertiesDialog()
	{
		StandardDialog newDialog = new StandardDialog(new ObjectMaintainerPropertiesPanel(this));
		newDialog.show();
    }
	          //*****---SHOW PROPERTIES DIALOG---******//
    
    
	public void EdgeClicked(EdgeClickedEvent e){}
	public void NodeClicked(NodeClickedEvent e){}

	
			//*****---Thread commands---******//
    public void start(){ try{ oldObjectDeleterThread=new Thread(this);oldObjectDeleterThread.start();} catch(Exception e){e.printStackTrace();}}
    // public void stop(){ try{ oldObjectDeleterThread.stop();} catch(Exception e){e.printStackTrace();}}
    public void sleep(long p){ try{ oldObjectDeleterThread.sleep(p);} catch(Exception e){e.printStackTrace();}}
    public void setPriority(int p) { try{oldObjectDeleterThread.setPriority(p);} catch(Exception e){e.printStackTrace();}}    
			//*****---Thread commands---******//

			//*****---GET/SET commands---******//
    public long GetNodeExpireTime() { return nodeExpireTime;}    
    public long GetEdgeExpireTime() { return edgeExpireTime;}    
    public long GetEdgeInitialPersisistance() { return edgeInitialPersistance;}    
    public long GetNodeInitialPersisistance() { return nodeInitialPersistance;}    
    public long GetExpirationCheckRate() { return expirationCheckRate;}  
    
    public ActivePanel GetProprietaryNodeInfoPanel(Integer pNodeNumber)
    {
    	return new ProprietaryNodeInfoPanel((NodeInfo)nodeInfo.get(pNodeNumber));
    }

    public ActivePanel GetProprietaryEdgeInfoPanel(Integer pSourceNodeNumber, Integer pDestinationNodeNumber)
    {
    	EdgeInfo info = (EdgeInfo)edgeInfo.get(pSourceNodeNumber, pDestinationNodeNumber);
    	if(info==null) return null;
    	return new ProprietaryEdgeInfoPanel(info);
    }

	public void SetNodeExpireTime(long p) { nodeExpireTime = p;}    
    public void SetEdgeExpireTime(long p) { edgeExpireTime = p;}    
    public void SetEdgeInitialPersisistance(long p) { edgeInitialPersistance = p;}    
    public void SetNodeInitialPersisistance(long p) { nodeInitialPersistance = p;}    
    public void SetExpirationCheckRate(long p) { expirationCheckRate = p;}    
//*****---GET/SET commands---******//

              //***************************************************************************
              //***************************************************************************
              //NODE MAINTANCE INFO CLASS
	public class NodeInfo
	{
		protected Integer nodeNumber;
		protected boolean base;
		protected Integer parent;
		protected Date timeCreated;
		protected Date timeLastSeen;
		protected Date secondToLastTimeSeen;
		protected Vector motesConnectedTo;
		protected boolean created;//this indicates whether everybody else has already been notified that this node exists (allows us to wait until we hear it more than once before creating it)
		
		public NodeInfo(Integer pNodeNumber, Date time)
		{
			nodeNumber = pNodeNumber;
			timeCreated = time;
			timeLastSeen = time;
			secondToLastTimeSeen = time;
			created = false;
		}
		
		public Integer GetNodeNumber(){return nodeNumber;}
		public Date GetTimeCreated()
		{
			return timeCreated;
		}
		
		public void SetTimeCreated(Date time)
		{
			timeCreated = time;
		}
		
		public Date GetTimeLastSeen()
		{
			return timeLastSeen;
		}
		
		public Date GetSecondToLastTimeSeen()
		{
			return secondToLastTimeSeen;
		}
 
 		public void SetTimeLastSeen(Date time)
		{
			secondToLastTimeSeen = timeLastSeen;
			timeLastSeen = time;
		}
		public boolean GetCreated(){return created;}
		public void SetCreated(boolean pCreated){created = pCreated;}
		public Integer GetParent(){return parent;}
		public void SetParent(Integer pParent){parent = pParent;}
		public void SetBase(boolean pbase){base = pbase;}
		public boolean GetBase(){return nodeNumber.intValue() == 0;}
	}
	          //EDGEMAINTAINECE INFO
	public class EdgeInfo
	{
		protected Integer sourceNodeNumber;
		protected Integer destinationNodeNumber;
		protected Date timeCreated;
		protected Date timeLastSeen;
		
		public EdgeInfo(Integer pSourceNodeNumber, Integer pDestinationNodeNumber, Date time)
		{
			sourceNodeNumber = pSourceNodeNumber;
			destinationNodeNumber = pDestinationNodeNumber;
			timeCreated = time;
			timeLastSeen = time;
		}
		
		public Integer GetSourceNodeNumber(){return sourceNodeNumber;}
		public Integer GetDestinationNodeNumber(){return destinationNodeNumber;}
		public Date GetTimeCreated()
		{
			return timeCreated;
		}
		
		public void SetTimeCreated(Date time)
		{
			timeCreated = time;
		}
		
		public Date GetTimeLastSeen()
		{
			return timeLastSeen;
		}
		
		public void SetTimeLastSeen(Date time)
		{
			timeLastSeen = time;
		}
	}
	          //NODE INFO PANEL
	public class ProprietaryNodeInfoPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		NodeInfo nodeInfo;
		
		public ProprietaryNodeInfoPanel(NodeInfo pNodeInfo)
		{
			tabTitle = "Creation";
			nodeInfo = pNodeInfo;
			setLayout(null);
//			Insets ins = getInsets();
			setSize(307,168);
			JLabel3.setToolTipText("The time in milliseconds that this node was first seen");
			JLabel3.setText("Time Created:");
			add(JLabel3);
			JLabel3.setBounds(12,36,108,24);
			JLabel4.setToolTipText("The time in milliseconds that this node was last seen");
			JLabel4.setText("Time Last Seen");
			add(JLabel4);
			JLabel4.setBounds(12,60,108,24);
			JTextField1.setNextFocusableComponent(JTextField2);
			JTextField1.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
			JTextField1.setText("1.5");
			add(JTextField1);
			JTextField1.setBounds(108,36,180,18);
			JTextField2.setNextFocusableComponent(JTextField3);
			JTextField2.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
			JTextField2.setText("3.2");
			add(JTextField2);
			JTextField2.setBounds(108,60,180,18);
			JLabel1.setToolTipText("The second to last time seen");
			JLabel1.setText("Time Before");
			add(JLabel1);
			JLabel1.setBounds(12,84,90,18);
			JTextField3.setNextFocusableComponent(JTextField1);
			JTextField3.setToolTipText("The second to last time seen");
			JTextField3.setText("4.5");
			add(JTextField3);
			JTextField3.setBounds(108,84,180,18);
			JLabel2.setText("Node Number:");
			add(JLabel2);
			JLabel2.setFont(new Font("Dialog", Font.BOLD, 16));
			JLabel2.setBounds(48,0,120,39);
			JLabel5.setToolTipText("The number used to identify this node");
			JLabel5.setText("jlabel");
			add(JLabel5);
			JLabel5.setForeground(java.awt.Color.blue);
			JLabel5.setFont(new Font("Dialog", Font.BOLD, 16));
			JLabel5.setBounds(180,0,48,33);

		}

		javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel4 = new javax.swing.JLabel();
		javax.swing.JTextField JTextField1 = new javax.swing.JTextField();
		javax.swing.JTextField JTextField2 = new javax.swing.JTextField();
		javax.swing.JLabel JLabel1 = new javax.swing.JLabel();
		javax.swing.JTextField JTextField3 = new javax.swing.JTextField();
		javax.swing.JLabel JLabel2 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel5 = new javax.swing.JLabel();
		
		public void ApplyChanges()
		{
//			nodeInfo.SetTimeCreated(new Date(JTextField1.getText()));
//			nodeInfo.SetTimeLastSeen(new Date(JTextField2.getText()));
		}
		
		public void InitializeDisplayValues()
		{
			JTextField1.setText(String.valueOf(nodeInfo.GetTimeCreated()));
			JTextField2.setText(String.valueOf(nodeInfo.GetTimeLastSeen()));
			JTextField3.setText(String.valueOf(nodeInfo.GetSecondToLastTimeSeen()));
			JLabel5.setText(String.valueOf(nodeInfo.GetNodeNumber()));
		}
	}	          
	          //NODE INFO PANEL
	          //EDGE INFO PANEL
	public class ProprietaryEdgeInfoPanel extends net.tinyos.tinydb.topology.Dialog.ActivePanel
	{
		EdgeInfo edgeInfo;
		
		public ProprietaryEdgeInfoPanel(EdgeInfo pedgeInfo)
		{
			tabTitle = "Creation";
			edgeInfo = pedgeInfo;
			setLayout(null);
//			Insets ins = getInsets();
			setSize(307,168);
			JLabel3.setToolTipText("The time in milliseconds that this node was first seen");
			JLabel3.setText("Time Created:");
			add(JLabel3);
			JLabel3.setBounds(24,60,108,24);
			JLabel4.setToolTipText("The time in milliseconds that this node was last seen");
			JLabel4.setText("Time Last Seen");
			add(JLabel4);
			JLabel4.setBounds(24,84,108,24);
			JTextField1.setNextFocusableComponent(JTextField2);
			JTextField1.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
			JTextField1.setText("1.5");
			add(JTextField1);
			JTextField1.setBounds(120,60,180,18);
			JTextField2.setNextFocusableComponent(JTextField1);
			JTextField2.setToolTipText("The scale of the coordinate system is determined by the user, and scaled automatically by the system to fit to the screen");
			JTextField2.setText("3.2");
			add(JTextField2);
			JTextField2.setBounds(120,84,180,18);
			JLabel2.setText("Source Node Number:");
			add(JLabel2);
			JLabel2.setBounds(24,12,156,12);
			JLabel1.setText("Destination Node Number");
			add(JLabel1);
			JLabel1.setBounds(24,36,150,15);
			JLabel5.setText("jlabel");
			add(JLabel5);
			JLabel5.setBounds(192,12,36,12);
			JLabel6.setText("jlabel");
			add(JLabel6);
			JLabel6.setBounds(192,36,36,18);

		}

		javax.swing.JLabel JLabel3 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel4 = new javax.swing.JLabel();
		javax.swing.JTextField JTextField1 = new javax.swing.JTextField();
		javax.swing.JTextField JTextField2 = new javax.swing.JTextField();
		javax.swing.JLabel JLabel2 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel1 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel5 = new javax.swing.JLabel();
		javax.swing.JLabel JLabel6 = new javax.swing.JLabel();
		
		public void ApplyChanges()
		{
			edgeInfo.SetTimeCreated(new Date(Long.getLong(JTextField1.getText()).longValue()));
			edgeInfo.SetTimeLastSeen(new Date(Long.getLong(JTextField2.getText()).longValue()));
		}
		
		public void InitializeDisplayValues()
		{
			JLabel5.setText(edgeInfo.GetSourceNodeNumber().toString());
			JLabel6.setText(edgeInfo.GetDestinationNodeNumber().toString());
			JTextField1.setText(String.valueOf(edgeInfo.GetTimeCreated()));
			JTextField2.setText(String.valueOf(edgeInfo.GetTimeLastSeen()));
		}
	}	          
	          //OBJECT MAINTAINER PROPERTIES PANEL
	          //to be shown in a standard dialog
	public class ObjectMaintainerPropertiesPanel extends ActivePanel
	{
		ObjectMaintainer objectMaintainer;
		
		public ObjectMaintainerPropertiesPanel(ObjectMaintainer pObjectMaintainer)
		{
			tabTitle = "Object Maintainer Properties";
			modal=true;
			objectMaintainer = pObjectMaintainer;

			setLayout(null);
			setSize(286,264);
			add(nodeExpire);
			nodeExpire.setBounds(36,12,156,52);
			NodeExpireLabel.setText("label1");
			add(NodeExpireLabel);
			NodeExpireLabel.setBounds(204,12,47,52);
			nodeExpireSlider.setMinimum(100);
			nodeExpireSlider.setMaximum(10000);
			nodeExpireSlider.setToolTipText("The time before this node is deleted, since it last seen.");
			// nodeExpireSlider.setBorder(bevelBorder1);
			nodeExpireSlider.setValue(100);
			add(nodeExpireSlider); 
			nodeExpireSlider.setBounds(60,48,192,24);
			nodeInitialPersistance.setText("Node Initial Persistance:");
			add(nodeInitialPersistance);
			nodeInitialPersistance.setBounds(36,60,156,52);
			nodeInitialPersistanceLabel.setText("label2");
			add(nodeInitialPersistanceLabel);
			nodeInitialPersistanceLabel.setBounds(204,60,47,52);
			nodeInitialPersistanceSlider.setMinimum(100);
			nodeInitialPersistanceSlider.setMaximum(10000);
			nodeInitialPersistanceSlider.setToolTipText("The time before a node is deleted, since it was first seen.");
			// nodeInitialPersistanceSlider.setBorder(bevelBorder1);
			nodeInitialPersistanceSlider.setOpaque(false);
			nodeInitialPersistanceSlider.setValue(100);
			add(nodeInitialPersistanceSlider); 
			nodeInitialPersistanceSlider.setForeground(java.awt.Color.lightGray);
			nodeInitialPersistanceSlider.setBounds(60,96,192,24);
			edgeExpire.setText("Edge Expire Time:");
			add(edgeExpire);
			edgeExpire.setBounds(36,108,156,52);
			edgeExpireLabel.setText("label3");
			add(edgeExpireLabel);
			edgeExpireLabel.setBounds(204,108,47,52);
			edgeExpireSlider.setMinimum(100);
			edgeExpireSlider.setMaximum(10000);
			edgeExpireSlider.setToolTipText("The time before an edge is deleted, since it was last seen");
			// edgeExpireSlider.setBorder(bevelBorder1);
			edgeExpireSlider.setValue(100);
			add(edgeExpireSlider); 
			edgeExpireSlider.setBounds(60,144,192,24);
			edgeInitialPersistance.setText("Edge Initial Persistance:");
			add(edgeInitialPersistance);
			edgeInitialPersistance.setBounds(36,156,156,52);
			edgeInitialPersistanceLabel.setText("label4");
			add(edgeInitialPersistanceLabel);
			edgeInitialPersistanceLabel.setBounds(204,156,47,52);
			edgeInitialPersistanceSlider.setMinimum(100);
			edgeInitialPersistanceSlider.setMaximum(10000);
			edgeInitialPersistanceSlider.setToolTipText("The time before an edge is deleted, since it was first seen.");
			// edgeInitialPersistanceSlider.setBorder(bevelBorder1);
			edgeInitialPersistanceSlider.setValue(100);
			add(edgeInitialPersistanceSlider); 
			edgeInitialPersistanceSlider.setForeground(java.awt.Color.lightGray);
			edgeInitialPersistanceSlider.setBounds(60,192,192,24);
			expirationCheckRate.setText("Expiration Check Rate");
			add(expirationCheckRate);
			expirationCheckRate.setBounds(36,204,159,51);
			expirationCheckRateLabel.setText("label5");
			add(expirationCheckRateLabel);
			expirationCheckRateLabel.setBounds(204,204,48,51);
			JLabel1.setToolTipText("1 second is 1000 milliseconds");
			expirationCheckRateSlider.setValue(100);
			JLabel1.setText("Note: all times are in milliseconds");
			add(JLabel1);
			JLabel1.setForeground(java.awt.Color.blue);
			JLabel1.setBounds(48,0,219,21);
			expirationCheckRateSlider.setMinimum(100);
			expirationCheckRateSlider.setMaximum(10000);
			expirationCheckRateSlider.setToolTipText("The rate at which the Object Maintainer goes through all the objects and deletes old ones.  ");
			// expirationCheckRateSlider.setBorder(bevelBorder1);
			add(expirationCheckRateSlider);
			expirationCheckRateSlider.setBackground(new java.awt.Color(204,204,204));
			expirationCheckRateSlider.setForeground(java.awt.Color.lightGray);
			expirationCheckRateSlider.setBounds(60,240,192,24);
		
			nodeExpire.setText("Node Expire Time:");
			//$$ bevelBorder1.move(0,306);
		
			SymChange lSymChange = new SymChange();
			nodeExpireSlider.addChangeListener(lSymChange);
			nodeInitialPersistanceSlider.addChangeListener(lSymChange);
			edgeExpireSlider.addChangeListener(lSymChange);
			edgeInitialPersistanceSlider.addChangeListener(lSymChange);
			expirationCheckRateSlider.addChangeListener(lSymChange);
		}
		
		javax.swing.JLabel nodeExpire = new javax.swing.JLabel();
		javax.swing.JLabel NodeExpireLabel = new javax.swing.JLabel();
		javax.swing.JSlider nodeExpireSlider = new javax.swing.JSlider();
		javax.swing.JLabel nodeInitialPersistance = new javax.swing.JLabel();
		javax.swing.JLabel nodeInitialPersistanceLabel = new javax.swing.JLabel();
		javax.swing.JSlider nodeInitialPersistanceSlider = new javax.swing.JSlider();
		javax.swing.JLabel edgeExpire = new javax.swing.JLabel();
		javax.swing.JLabel edgeExpireLabel = new javax.swing.JLabel();
		javax.swing.JSlider edgeExpireSlider = new javax.swing.JSlider();
		javax.swing.JLabel edgeInitialPersistance = new javax.swing.JLabel();
		javax.swing.JLabel edgeInitialPersistanceLabel = new javax.swing.JLabel();
		javax.swing.JSlider edgeInitialPersistanceSlider = new javax.swing.JSlider();
		javax.swing.JLabel expirationCheckRate = new javax.swing.JLabel();
		javax.swing.JLabel expirationCheckRateLabel = new javax.swing.JLabel();
		javax.swing.JLabel JLabel1 = new javax.swing.JLabel();
		javax.swing.JSlider expirationCheckRateSlider = new javax.swing.JSlider();
		// com.symantec.itools.javax.swing.borders.BevelBorder bevelBorder1 = new com.symantec.itools.javax.swing.borders.BevelBorder();

            	//---------------------------------------------------------------------
            	//APPLY CHANGES
		public void ApplyChanges()
		{
			objectMaintainer.SetNodeExpireTime(nodeExpireSlider.getValue());
			objectMaintainer.SetEdgeExpireTime(edgeExpireSlider.getValue());
    		objectMaintainer.SetEdgeInitialPersisistance(edgeInitialPersistanceSlider.getValue());
    		objectMaintainer.SetNodeInitialPersisistance(nodeInitialPersistanceSlider.getValue());
    		objectMaintainer.SetExpirationCheckRate(expirationCheckRateSlider.getValue());
		}
            	//APPLY CHANGES
            	//---------------------------------------------------------------------
		

            	//---------------------------------------------------------------------
            	//INITIALIZE DISPLAY VALUES
		public void InitializeDisplayValues()
		{
			NodeExpireLabel.setText(String.valueOf(objectMaintainer.GetNodeExpireTime()));
			nodeExpireSlider.setValue((int)objectMaintainer.GetNodeExpireTime());
			nodeInitialPersistanceLabel.setText(String.valueOf(objectMaintainer.GetNodeInitialPersisistance()));
			nodeInitialPersistanceSlider.setValue((int)objectMaintainer.GetNodeInitialPersisistance());
			edgeExpireLabel.setText(String.valueOf(objectMaintainer.GetEdgeExpireTime()));
			edgeExpireSlider.setValue((int)objectMaintainer.GetEdgeExpireTime());
			edgeInitialPersistanceLabel.setText(String.valueOf(objectMaintainer.GetEdgeInitialPersisistance()));
			edgeInitialPersistanceSlider.setValue((int)objectMaintainer.GetEdgeInitialPersisistance());
			expirationCheckRateLabel.setText(String.valueOf(objectMaintainer.GetExpirationCheckRate()));
			expirationCheckRateSlider.setValue((int)objectMaintainer.GetExpirationCheckRate());

		    	//This function is called by a thread that runs in the background
		    	//and updates the values of the Active Panels so they are always
		    	//up to date.
		}
            	//INITIALIZE DISPLAY VALUES
            	//---------------------------------------------------------------------

		class SymChange implements javax.swing.event.ChangeListener
		{
			public void stateChanged(javax.swing.event.ChangeEvent event)
			{
				Object object = event.getSource();
				if (object == nodeExpireSlider)
					nodeExpireSlider_stateChanged(event);
				else if (object == nodeInitialPersistanceSlider)
					nodeInitialPersistanceSlider_stateChanged(event);
				else if (object == edgeExpireSlider)
					edgeExpireSlider_stateChanged(event);
				else if (object == edgeInitialPersistanceSlider)
					edgeInitialPersistanceSlider_stateChanged(event);
				else if (object == expirationCheckRateSlider)
					expirationCheckRateSlider_stateChanged(event);
			}
		}

		void nodeExpireSlider_stateChanged(javax.swing.event.ChangeEvent event)
		{
			// to do: code goes here.
				 
			nodeExpireSlider_stateChanged_Interaction1(event);
		}

		void nodeExpireSlider_stateChanged_Interaction1(javax.swing.event.ChangeEvent event)
		{
			try {
				// convert int->class java.lang.String
				NodeExpireLabel.setText(java.lang.String.valueOf(nodeExpireSlider.getValue()));
			} catch (java.lang.Exception e) {
			}
		}

		void nodeInitialPersistanceSlider_stateChanged(javax.swing.event.ChangeEvent event)
		{
			// to do: code goes here.
				 
			nodeInitialPersistanceSlider_stateChanged_Interaction1(event);
		}

		void nodeInitialPersistanceSlider_stateChanged_Interaction1(javax.swing.event.ChangeEvent event)
		{
			try {
				// convert int->class java.lang.String
				nodeInitialPersistanceLabel.setText(java.lang.String.valueOf(nodeInitialPersistanceSlider.getValue()));
			} catch (java.lang.Exception e) {
			}
		}

		void edgeExpireSlider_stateChanged(javax.swing.event.ChangeEvent event)
		{
			// to do: code goes here.
				 
			edgeExpireSlider_stateChanged_Interaction1(event);
		}

		void edgeExpireSlider_stateChanged_Interaction1(javax.swing.event.ChangeEvent event)
		{
			try {
				// convert int->class java.lang.String
				edgeExpireLabel.setText(java.lang.String.valueOf(edgeExpireSlider.getValue()));
			} catch (java.lang.Exception e) {
			}
		}

		void edgeInitialPersistanceSlider_stateChanged(javax.swing.event.ChangeEvent event)
		{
			// to do: code goes here.
				 
			edgeInitialPersistanceSlider_stateChanged_Interaction1(event);
		}

		void edgeInitialPersistanceSlider_stateChanged_Interaction1(javax.swing.event.ChangeEvent event)
		{
			try {
				// convert int->class java.lang.String
				edgeInitialPersistanceLabel.setText(java.lang.String.valueOf(edgeInitialPersistanceSlider.getValue()));
			} catch (java.lang.Exception e) {
			}
		}

		void expirationCheckRateSlider_stateChanged(javax.swing.event.ChangeEvent event)
		{
			// to do: code goes here.
				 
			expirationCheckRateSlider_stateChanged_Interaction1(event);
		}

		void expirationCheckRateSlider_stateChanged_Interaction1(javax.swing.event.ChangeEvent event)
		{
			try {
				// convert int->class java.lang.String
				expirationCheckRateLabel.setText(java.lang.String.valueOf(expirationCheckRateSlider.getValue()));
			} catch (java.lang.Exception e) {
			}
		}
	}
}
