// $Id: TinyDBMain.java,v 1.31 2004/02/10 22:29:23 whong Exp $

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
import net.tinyos.message.*;
import net.tinyos.packet.*;
import net.tinyos.sf.*;
import net.tinyos.util.DTNStub;
import net.tinyos.util.PrintStreamMessenger;
import java.io.*;

/** TinyDBMain creates the main UI for the TinyDB java
 classes.
 */
public class TinyDBMain {
    /**
	 * @param args the command line arguments
	 */
    public static void main(String args[]) {
		
	if (!parseArgs(args)) return;
	    try {
		initMain();
	    } catch (IOException e) {
		System.out.println("Failed to initialize network.");
		if (debug) e.printStackTrace();
	    }
	    
	    String commandString = Config.getParam("show-command-window");
	    if (commandString != null) {
			if (commandString.toLowerCase().equals("true"))
				showControlPanel = true;
			else
				showControlPanel = false;
	    }

	    String statusString = Config.getParam("show-status-window");
	    if (statusString != null) {
		if (statusString.toLowerCase().equals("true"))
		    hideStatusWin = false;
		else
		    hideStatusWin = true;
	    }

	    //now, get status of running motes
	    status = new TinyDBStatus(network, mif, !cmdLine && !hideStatusWin);
	    status.requestStatus(1000, 1);
	    MainFrame.setNextQid((initQid != -1)?(byte)initQid:(byte)(status.getMaxQid()+1));
	    status.setLocation(800,330);
		
	    //show GUI / cmd frame
	    if (cmdLine) {
			CmdLineOutput cmdLine = new CmdLineOutput(network, cmdLineQuery);
			while (true) {
				try {
					Thread.currentThread().sleep(1000);
				} catch(Exception e) {
				}
			}
	    } else {
			
			if (showControlPanel) {
				CmdFrame cmf = new CmdFrame(mif);
				cmf.setLocation(800,30);
				cmf.show();
			}
			
			mf = new MainFrame(network, startGuiInterface);
			mf.setLocation(5,30);
			mf.show();
	    }
		
		
    }
    
    /** Initialize the static variables that TinyDB needs to have set up to run
	 Note that this does not show any of the TinyDB UI, so it can be used
	 in apps that have their own user interface
	
	 @param configFile The name of the configuration file to use.
	 */
    public static void initMain(String configFileName) throws IOException{
		TinyDBMain.configFile = configFileName;
		initMain();
		
    }
    
    /** Initialize the static variables that TinyDB needs to have set up to run
	 Note that this does not show any of the TinyDB UI, so it can be used
	 in apps that have their own user interface
	 */
    public static void initMain() throws IOException{
	Config.init(configFile);
	Catalog c = new Catalog(Config.getParam("catalog-file"));
	Catalog.curCatalog = c;
		
	String groupStr = Config.getParam("am-group-id");
	if (groupStr == null)
	    groupid = GROUP_ID;
	else {
	    try {
		groupid = new Byte(groupStr).byteValue();
		if (debug) System.out.println("GROUPID : " + groupid);
	    } catch (NumberFormatException e) {
		System.out.println("Bad am-group-id entry in config file: " + groupStr);
		groupid = GROUP_ID;
	    }
	}
	
	String startSfString = Config.getParam("start-sf");
	if (startSfString != null)
	    if (startSfString.toLowerCase().equals("false"))
		startSerialForwarder=false;
	String useGBRootStr = Config.getParam("gb-root");
	if (useGBRootStr != null && useGBRootStr.equalsIgnoreCase("true"))
	    useGBRoot = true;
	
	//open radio comm
	try {
	    Thread t;
	    
	    if (getMoteIF() == null)
		throw new IOException();
	    
	    t = new Thread(mif);
	    t.start();
	    network = new TinyDBNetwork(mif);
	    addQueryListener(network);
	    
	    
	} catch (IOException e) {
	    if (debug) { e.printStackTrace();
	    System.out.println("Open radio comm failed -- network won't work.");
	    }
	    throw e;
	}
	
    }
	
    /** Helper routine to handle the common steps in sending a query
	 into the network.
	 @param q The query to inject
	 @param rl The result listner to receive (processed) results from
	 this query.
	 */
    public static void injectQuery(TinyDBQuery q, ResultListener rl) throws IOException{
		//add the query to list of queries we know about
		notifyAddedQuery(q);
		// register the listener for results from this query
		network.addResultListener(rl, true, q.getId());
		//inject the query
		network.sendQuery(q);
		
    }
    
    // The following methods are used to register/remove QueryListeners
    // that are notified whenever a query is started or stopped
    
    
    /** Register the specified QueryListener.  The listener will be notified
	 everytime notifyAddedQuery or notifyRemovedQuery is called.
	 */
    public static void addQueryListener(QueryListener ql) {
		qls.addElement(ql);
    }
	
    /** Deregister the specified QueryListener */
    public static void removeQueryListener(QueryListener ql) {
		qls.removeElement(ql);
    }
	
    /** Notify all currently registered QueryListeners with a addQuery message */
    public static void notifyAddedQuery(TinyDBQuery q) {
		Enumeration e;
		e = qls.elements();
		while (e.hasMoreElements()) {
			QueryListener ql = (QueryListener)e.nextElement();
			ql.addQuery(q);
		}
    }
	
    /** Notify all currently register QueryListeners with a removeQuery message */
    public static void notifyRemovedQuery(TinyDBQuery q) {
		Enumeration e;
		e = qls.elements();
		while (e.hasMoreElements()) {
			QueryListener ql = (QueryListener)e.nextElement();
			ql.removeQuery(q);
		}
    }
	
    static boolean parseArgs(String[] args) {
		boolean setInterface = false;
		try {
			for (int i = 0; i < args.length; i++) {
				if (args[i].equals("-text")) {
					startGuiInterface = false;
					if (setInterface) {
						System.out.println("-text option conflicts with previous input window option. \n" + usage);
						return false;
					}
					setInterface = true;
				}
				else if (args[i].equals("-cmdwindow"))
					showControlPanel = true;
				else if (args[i].equals("-gui")) {
					startGuiInterface = true;
					if (setInterface) {
						System.out.println("-gui option conflicts with previous input window option. \n" + usage);
						return false;
					}
					setInterface = true;
				} else if (args[i].equals("-configfile")) {
					configFile = args[++i];
				} else if (args[i].equals("-run")) {
					cmdLine = true;
					cmdLineQuery = args[++i];
				} else if (args[i].equals("-debug")) {
					debug = true;
				} else if (args[i].equals("-sim")) {
					simulate = true;
				} else if (args[i].equals("-qid")) {
					try {
						initQid = new Integer(args[++i]).intValue();
					} catch (NumberFormatException e) {
						System.out.println("Invalid query ID : " + args[i]);
						return false;
					}
				} else if (args[i].equals("-gsk")) {
				    System.out.println("-gsk flag is deprecated.  TinyDB always runs in GSK mode!");
				} else {
				    System.out.println("Unknown argument: " + args[i]);
				    System.out.println(usage);
				    return false;
				}
			}
		} catch (ArrayIndexOutOfBoundsException e) {
			System.out.println("Missing expected command line argument! \n" + usage);
			return false;
		}
		
		return true;
    }
	
	
    /** RootId is the id of the mote that is the root of the query */
	static short getRootId()
	{
		if (cmdLine)
			return new Short(Config.getParam("root-id")).shortValue();
		else if (mf != null)
			return (short)mf.getRootId();
		return 0;
	}
	
    static MoteIF getMoteIF() throws IOException{
	String host = "localhost";
	short port = 9000;
	String commPort = Config.getParam("sf-comm-port");
	String baud = Config.getParam("sf-baud-rate");
	String dtnStr = Config.getParam("use-dtn");
	boolean useDTN = false;
	String bundleAgent = null;
	
	if (commPort == null)
	    commPort = "COM1";
	sfCommPort = commPort;
	
	if (dtnStr != null && dtnStr.equalsIgnoreCase("true")) {
	    useDTN = true;
	    bundleAgent = Config.getParam("dtn-agent");
	}
		
	if (mif == null)  {
	    if (useDTN) {
		try {
		    mif = new MoteIF(new DTNStub(bundleAgent, 56),
				     groupid, 56, false);
		}
		catch (Exception e) {
		    e.printStackTrace();
		}
	    }
	    else{
			
		try {
		    String commString = simulate?"tossim-serial":Config.getParam("comm-string");
		    if (DEBUG) System.out.println("Creating PhoenixSource with " + commString); 
		    PhoenixSource ps = BuildSource.makePhoenix(commString, PrintStreamMessenger.err);
			ps.setResurrection();
		    mif = new MoteIF(ps, groupid);
		}
		catch (Exception e) {
		    e.printStackTrace();
		}
	    }
	}
	return mif;
    }
    
    public static MoteIF mif = null;
	
    public static byte groupid;
	public static String sfHost;
	public static short sfPort;
	public static String sfCommPort;
	
    public static TinyDBNetwork network;
    private static TinyDBStatus status;
	
	public static boolean useGBRoot = false; /* use GenericComm root */
	
    public static boolean debug = false;
    static boolean startSerialForwarder = true;
    static boolean startGuiInterface = true;
    static boolean showControlPanel = false;
    static boolean hideStatusWin = true;
    public static boolean simulate = false;
    private static boolean cmdLine = false;
    private static String cmdLineQuery;
    private static int initQid = -1;
	
    //private static String configFile = "tinydb.conf";
    private static String configFile = "net/tinyos/tinydb/tinydb.conf";
	
    static final String usage = "Usage: java TinyDBMain [-text|-gui] [-cmdwindow] [-configfile file] [-run query] [-debug] [-qid n] \n\t-text: Use text input window \n\t-gui: Use gui input window (default) \n\t-cmdwindow: Display the command window. \n\t-configfile: The name of the configuration file to use (default: " + configFile + ")\n\t-run: Run the specified query on the command line\n\t-debug: Enable debugging messages\n\t-sim: Run in \"simulation\" mode. \n\t-qid n: Start with the specified query id";
	
    private static Vector qls = new Vector(); //vector of query listeners
	
    private static final int GROUP_ID = 105;
	
    private static MainFrame mf = null;
    
	
    private static final boolean DEBUG = true;
}
