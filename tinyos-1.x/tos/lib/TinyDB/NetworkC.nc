// $Id: NetworkC.nc,v 1.24 2003/10/07 21:46:20 idgay Exp $

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
/* Routing component for TinyDB.  Can receive and send
   data and query messages.  Data messages are tuples
   or aggregate values.  Queries represent portions
   of queries being injected into the network.

   In the TAG world, query messages flood down the routing tree,
   and data messages are sent up the network (to the node's) parent
   towards the root.  Obviously, there are other routing mechanisms
   that might make sense,  but the routing system needs to be careful
   to do duplicate elimination -- which may be hard since this API
   doesn't export the contents of the data messages.

   Note that the send routines in this component depend on the higher
   level tuple router in several ugly ways:

   1) They expect that the TOS_MsgPtr's deliver have space for
   the appropriate TINYDB_NETWORK header (type DbMsgHdr) at the
   top.

   The basic routing algorithm implemented by this component works as follows:
   
   1) Each mote maintains a small buffer of "neighbor" motes it can hear
   2) For each neighbor, the mote tracks the signal quality by observing sequence
   numbers on messages from that neighbor degrading quality when messages are missed
   3) Each mote picks a parent from its neighbors;  ideally, parents will be
   motes that have a high signal quality and are close to the root
   4) Once a parent has been selected, motes stick to that parent unless the quality of
   the parent degrades substantially (even if another parent that is closer to the
   root with similar quality appears) -- this "topology stability" property is
   important for insuring correct computation of aggregates.

   These data structures have been updated to be parameterized by ROOT_ID, which allows us
   maintain several routing trees.  Note that we keep only one neighbor list
   (and estimate of quality per neighbor), but that we keep multiple levels for 
   each neighbor, ourself, and our parents.

   Authors:  Sam Madden -- basic structure, current maintainer
			 Wei Hong -- conform to standard Network interface
             Joe Hellerstein -- initial implementation of neighbor tracking and parent selection
*/



configuration NetworkC 
{
	provides 
	{
		interface Network;
		interface StdControl;
		interface NetworkMonitor;
	}
}
implementation
{
	components NetworkM, GENERICCOMM as Comm, LedsC, RandomLFSR
#ifdef kSUPPORTS_EVENT
	, TinyDBEvent
#endif
	, TupleRouterM, TinyDBCommand;

	Network = NetworkM;
	NetworkMonitor = NetworkM;
	StdControl = NetworkM;

	NetworkM.SendDataMsg -> Comm.SendMsg[kDATA_MESSAGE_ID];
	NetworkM.SendQueryMsg -> Comm.SendMsg[kQUERY_MESSAGE_ID];
	NetworkM.SendQueryRequest -> Comm.SendMsg[kQUERY_REQUEST_MESSAGE_ID];
	NetworkM.DebugMsg -> Comm.SendMsg[1];
	NetworkM.SchemaMsg -> Comm.SendMsg[kCOMMAND_MESSAGE_ID];
#ifdef kSUPPORTS_EVENTS
	NetworkM.EventMsg -> Comm.SendMsg[kEVENT_MESSAGE_ID];
#endif
#ifdef kSTATUS
	NetworkM.SendStatusMessage -> Comm.SendMsg[kSTATUS_MESSAGE_ID];
#endif

	NetworkM.RcvDataMsg -> Comm.ReceiveMsg[kDATA_MESSAGE_ID];
	NetworkM.RcvQueryMsg -> Comm.ReceiveMsg[kQUERY_MESSAGE_ID];
#ifdef kQUERY_SHARING
	NetworkM.RcvRequestMsg -> Comm.ReceiveMsg[kQUERY_REQUEST_MESSAGE_ID];
#endif
	NetworkM.RcvCommandMsg -> Comm.ReceiveMsg[kCOMMAND_MESSAGE_ID];
#ifdef kSUPPORTS_EVENTS
	NetworkM.RcvEventMsg -> Comm.ReceiveMsg[kEVENT_MESSAGE_ID];
#endif
#ifdef kSTATUS
	NetworkM.RcvStatusMessage -> Comm.ReceiveMsg[kSTATUS_MESSAGE_ID];
#endif

	NetworkM.Leds -> LedsC;
	NetworkM.Random -> RandomLFSR;

	NetworkM.CommandUse -> TinyDBCommand;
#ifdef kSUPPORTS_EVENTS
	NetworkM.EventUse -> TinyDBEvent;
#endif
	NetworkM.QueryProcessor -> TupleRouterM;

	NetworkM.SubControl -> Comm;
}
