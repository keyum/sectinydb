// $Id: CommandMsgs.java,v 1.9 2003/10/07 21:46:07 idgay Exp $

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

import net.tinyos.message.*;
import java.io.*;

/** Class with static functions to generate message arrays that
    can be used to invoke commands on Db motes.
*/
public class CommandMsgs {
    /** AM Message ID used for command messages */
    public static final byte CMD_MSG_TYPE = 103;
    private static final int MSG_LEN=30;
    /** The reset command resets motes (like toggling the power switch 
     @param targetId The id of the mote that should receive this message 
    */
    public static Message resetCmd(short targetId) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
	int offset;

	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	setCommandName(cmdMessage, "Reset");
	return cmdMessage;

	
    }

    /** Sets the length of the log (number of messages returned by dump log
	@deprecated
     */
    public static Message setLogLen(short targetId, short offset) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
	int pos;

	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	pos = setCommandName(cmdMessage, "ResetLog");
	cmdMessage.setElement_data(pos++, (byte)(offset & 0xFF));
	cmdMessage.setElement_data(pos++,(byte)((targetId & 0xFF00) >> 8));

	return cmdMessage;



    }

    /** Causes the mote to spill the current contents of the EEPROM log 
     @deprecated
     */
    public static Message dumpLog(short targetId) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
	int pos;
	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	pos = setCommandName(cmdMessage, "DumpLog");
	cmdMessage.setElement_data(pos++,(byte)0);
	cmdMessage.setElement_data(pos++,(byte)0);
	
	return cmdMessage;



    }

    /** Constrains the network topology to have the specified fanout 
	@param targetId The ID of the mote that should receive this message
	@param fanout The topology fanout.  Motes are constrained to choose
	one of fanout parents (e.g. if fanout = 2, mote id 3 can pick motes
	1 or 2 as a parent.)
     */
    public static Message setFanout(short targetId, char fanout) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	int pos = setCommandName(cmdMessage, "SetTopo");
	cmdMessage.setElement_data(pos++,(byte)fanout);

	return cmdMessage;
    }

    /** Sets the value of the radio strength potentiometer (0 - 100), 0 is largest
     @param targetId The recipient of this message
    @param pot The value of the potentiometer*/
    public static Message setPot(short targetId, char pot) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);

	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	int pos = setCommandName(cmdMessage,"SetPot");
	cmdMessage.setElement_data(pos++,(byte)pot);

	return cmdMessage;


    }

    /** Enabled "centralized" routing, where no aggregation is performed in network
	and data is simply forwarded to the root.
    */
    public static Message setCentralized(short targetId, boolean centralized) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);

	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	int pos = setCommandName(cmdMessage, "SetCent");
	cmdMessage.setElement_data(pos++,centralized?(byte)1:(byte)0);

	return cmdMessage;
    }

    
    /** Fixed comm means that motes transmit in in the time slot corresponding to their
	local id * 2;  unfixed comm means mote xmit in a random slot selected uniformly
	in the range (0 .. local cell size estimate)
    */
    public static Message setFixedComm(short targetId, boolean fixed) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);

	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	int pos = setCommandName(cmdMessage, "FixComm");
	cmdMessage.setElement_data(pos++,fixed?(byte)1:(byte)0);

	return cmdMessage;
    }
    
    /** Stop the magnetometer from oversampling (for power conservation)*/
    public static Message stopMagCmd(short targetId) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
	
	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	setCommandName(cmdMessage, "StopMag");
		      
	return cmdMessage;
	
    }

    public static Message setSounderCmd(short targetId) {
	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);

	cmdMessage.set_nodeid(targetId);

	cmdMessage.set_seqNo(getNextSeqNo());
	int pos = setCommandName(cmdMessage, "SetSnd");
	cmdMessage.setElement_data(pos++,(byte)0);
	cmdMessage.setElement_data(pos++,(byte)2);
		      
	return cmdMessage;
	
    }


    public static Message addAttrCmd(short targetId, char[] name, byte t, long val) {
      int namelen = name.length;
      int offset = 0;
      String cmd = "addattr";
      int cmdlen = cmd.length();

      if (namelen > 8) namelen = 8;

      CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
      cmdMessage.set_nodeid(targetId);
      
	cmdMessage.set_seqNo(getNextSeqNo());
      for (int i = 0; i < cmdlen; i++) {
	cmdMessage.setElement_data(offset++, (byte)cmd.charAt(i));
      }
      cmdMessage.setElement_data(offset++, (byte)0); //null term
      for (int i =0; i < namelen; i++) {
	cmdMessage.setElement_data(offset++, (byte)name[i]);
      }
      cmdMessage.setElement_data(offset++, (byte)0); //null term
      cmdMessage.setElement_data(offset++,t); //type
      cmdMessage.setElement_data(offset++,(byte)(val & 0xFF));
      cmdMessage.setElement_data(offset++,(byte)((val & 0xFF00) >> 8));
      cmdMessage.setElement_data(offset++,(byte)((val & 0xFF0000) >> 16));
      cmdMessage.setElement_data(offset++,(byte)((val & 0xFF000000) >> 24));

      return cmdMessage;
    }

    public static Message logAttrCmd(short targetId, char[] name, long samplePeriod, short nsamples) {
      int namelen = name.length;
      int offset = 0;
      String cmd = "logattr";
      int cmdlen = cmd.length();

      if (namelen > 8) namelen = 8;

      CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
      cmdMessage.set_nodeid(targetId);
      
	cmdMessage.set_seqNo(getNextSeqNo());
      for (int i = 0; i < cmdlen; i++) {
	cmdMessage.setElement_data(offset++, (byte)cmd.charAt(i));
      }
      cmdMessage.setElement_data(offset++, (byte)0); //null term
      for (int i =0; i < namelen; i++) {
	cmdMessage.setElement_data(offset++, (byte)name[i]);
      }
      cmdMessage.setElement_data(offset++, (byte)0); //null term
      cmdMessage.setElement_data(offset++,(byte)(samplePeriod & 0xFF));
      cmdMessage.setElement_data(offset++,(byte)((samplePeriod & 0xFF00) >> 8));
      cmdMessage.setElement_data(offset++,(byte)((samplePeriod & 0xFF0000) >> 16));
      cmdMessage.setElement_data(offset++,(byte)((samplePeriod & 0xFF000000) >> 24));
      cmdMessage.setElement_data(offset++,(byte)(nsamples & 0xFF));
      cmdMessage.setElement_data(offset++,(byte)((nsamples & 0xFF00) >> 8));

      return cmdMessage;
    }

    static Message setLifetimeCmd(short targetId, byte qid, short lifetimeHrs) {
	String command = new String("life");
	int cmdLen = command.length();
	int offset = 0;

	CommandMsg cmdMessage = new CommandMsg(MSG_LEN);
	cmdMessage.set_nodeid(targetId);
	cmdMessage.set_seqNo(getNextSeqNo());
	offset = setCommandName(cmdMessage, command);
	cmdMessage.setElement_data(offset++,qid);
	cmdMessage.setElement_data(offset++,(byte)(lifetimeHrs & 0xFF));
	cmdMessage.setElement_data(offset++,(byte)((lifetimeHrs & 0xFF00) >> 8));
	
	return cmdMessage;
    }

    public static Message fireEvent(short targetId) {
	// EventMsg msg = new EventMsg(11);
	// msg.set_nodeid(targetId);
	// setEventName(msg,"evtTest");
	// return msg;
	return null;
    }

    static int setCommandName(CommandMsg m, String s) {
	int i;
	for (i = 0; i < s.length(); i++) {
	    m.setElement_data(i, (byte)s.charAt(i));
	}
	m.setElement_data(i++,(byte)0); //null terminate
	return i;
    }

	/*
    static int setEventName(EventMsg m, String s) {
	int i;
	for (i = 0; i < s.length(); i++) {
	    m.setElement_data(i, (byte)s.charAt(i));
	}
	m.setElement_data(i++,(byte)0); //null terminate
	return i;
    }
	*/

    public static int getLastSeqNo() {
	return seqNo;
    }

    public static void setLastSeqNo(int seqNo) {
	CommandMsgs.seqNo = seqNo;
    }

    public static int getNextSeqNo() {
	Integer seq;
	if (seqNo == 0) {
	    FileInputStream fis;
	    ObjectInputStream ois;


	    try {
		fis = new FileInputStream("cmdseqno.ser");
		ois = new ObjectInputStream(fis);
		seq = (Integer)ois.readObject();
		seqNo = seq.intValue();
		if (TinyDBMain.debug) System.out.println("Beginning with sequence number: " + seqNo);
		ois.close();
	    } catch (IOException e) {
		if (TinyDBMain.debug) System.out.println("FAILED TO READ SEQUENCE NUMBER");
	    } catch (ClassNotFoundException e) {
	    }

	}

	seqNo++;
	
	FileOutputStream fos;
	ObjectOutputStream oos;
	seq = new Integer(seqNo);
	try {
	    fos = new FileOutputStream("cmdseqno.ser");
	    oos = new ObjectOutputStream(fos);
	    oos.writeObject(seq);
	    oos.close();
	} catch (IOException e) {
	    System.out.println("FAILED TO INCREMENT SEQUENCE NUMBER");
	}

	return seqNo;
    }
    
    private static int seqNo = 0;

    
}
