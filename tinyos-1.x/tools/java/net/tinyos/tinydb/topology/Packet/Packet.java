// $Id: Packet.java,v 1.2 2003/10/07 21:46:08 idgay Exp $

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
package net.tinyos.tinydb.topology.Packet;

import java.util.*;
import net.tinyos.tinydb.topology.util.*;
import net.tinyos.tinydb.topology.*;
import net.tinyos.tinydb.*;

	          //This class will hold all information about the packets
	          //as the packets change between versions, the static variables in this class
	          //can be changed to reflect changes, thereby keeping the packet specifics
	          //contained in this class and increasing modularity
public class Packet
{
	public static final int NODEID_IDX	=	1;
	public static final int PARENT_IDX	=	2;
	public static final int LIGHT_IDX	=	3;
	public static final int TEMP_IDX	=	4;
	public static final int VOLTAGE_IDX	=	5;
	private static int currentValueIdx = LIGHT_IDX;
	private Vector resultVector;
	public Packet(QueryResult qr)
	{
		resultVector = qr.resultVector();
	} 
	public Integer getNodeId()
	{
		return new Integer((String)resultVector.elementAt(NODEID_IDX));
	}
	public Integer getParent()
	{
		return new Integer((String)resultVector.elementAt(PARENT_IDX));
	}
	public int getValue()
	{
		return Integer.parseInt((String)resultVector.elementAt(currentValueIdx));
	}
	public static void setCurrentValueIdx(int idx)
	{
		currentValueIdx = idx;
	}
	// XXX preserved for backward compatibility to some Surge code
	public Vector CreateRoutePathArray()
	{
		Vector v = new Vector(2);
		v.addElement(getNodeId());
		v.addElement(getParent());
		return v;
	}
}
