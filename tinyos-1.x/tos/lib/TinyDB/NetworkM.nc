// $Id: NetworkM.nc,v 1.3 2003/10/07 21:46:20 idgay Exp $

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
/*
 * Authors:	Sam Madden
 *              Design by Sam Madden, Wei Hong, and Joe Hellerstein
 * Date last modified:  6/26/02
 *
 *
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
             Joe Hellerstein -- initial implementation of neighbor tracking and parent selection
*/

/**
 * @author Sam Madden
 * @author Design by Sam Madden
 * @author Wei Hong
 * @author and Joe Hellerstein
 */


includes TinyDB;

module NetworkM {

  provides {
    interface Network;
    interface StdControl;
    interface NetworkMonitor;
  }

  uses {
    interface SendMsg as SendDataMsg;
    interface SendMsg as SendQueryMsg;
    interface SendMsg as SendQueryRequest;
    interface SendMsg as DebugMsg;
    interface SendMsg as SchemaMsg;
#ifdef kSUPPORTS_EVENTS
    interface SendMsg as EventMsg;
#endif
#ifdef kSTATUS
    interface SendMsg as SendStatusMessage;
#endif

    interface ReceiveMsg as RcvDataMsg;
    interface ReceiveMsg as RcvQueryMsg;
#ifdef kQUERY_SHARING
    interface ReceiveMsg as RcvRequestMsg;
#endif
    interface ReceiveMsg as RcvCommandMsg;
#ifdef kSUPPORTS_EVENTS
    interface ReceiveMsg as RcvEventMsg;
#endif
#ifdef kSTATUS
    interface ReceiveMsg as RcvStatusMessage;
#endif

    interface CommandUse;
#ifdef kSUPPORTS_EVENTS
    interface EventUse;
#endif
    interface Leds;
    interface Random;

    interface QueryProcessor;
	interface StdControl as SubControl;
  }
      
}

implementation {
  enum {
    LEVEL_UNKNOWN = -1,
    PARENT_UNKNOWN = -1,
    BAD_IX = -1,
    UNKNOWN_ROOT = -1,
    PARENT_RESELECT_INTERVAL = 5, //5 epochs
    PARENT_LOST_INTERVAL = 10, //5 epochs
    TIME_OF_FLIGHT = 0,
    NUM_RELATIVES = 5,
    MAX_PROB_THRESH = 127,  //only switch parents if there's a node thats a lot more reliable
    ALPHABITS = 2, // We do a moving average at time t where
                  // avg_t = avg_{t-1}*(1-alpha) + alpha*newvalue
                  // Since we're using integers, we shift by ALPHABITS, rather than multiplying
                  // by a fraction.
                  // so ALPHABITS=2 is like alpha = 0.25 (i.e. divide by 4)
    NACKALPHA= 4, //alpha bits to use on a failed ack
    QUERY_RETRIES = 5,
    NUM_ROOTS = 4,
    DATA_RETRIES = 0, //don't retry data messages for now, since we have no way of eliminating duplicates
  };


  uint16_t mSendCount; // increment each epoch
  // We track NUM_RELATIVES parents potential parents.
  // For each, we will track the mean # of drops of msgs from that "relative".
  char mRelatives[NUM_RELATIVES]; // an array of senders we're tracking potential parents
  char mRelOccupiedBits; // occupancy bitmap for slots in the relatives array
  short mParentIx[NUM_ROOTS]; // the current parent's index in the "relatives" array
                  // invariant: parentIx < NUM_RELATIVES
                  // invariant: relOccupiedBits is on for parentIx
  unsigned short mLastIdxRelative[NUM_RELATIVES]; // last idx # from this rel
  unsigned char mCommProb[NUM_RELATIVES]; // an 8-bit weighted moving average of
                                         // delivery success (delivered = 255,
                                         // dropped = 0).
  short mRoots[NUM_ROOTS];
  char mRelLevel[NUM_ROOTS][NUM_RELATIVES];  // current level of rel

  TOS_MsgPtr mMsg;
  TOS_Msg mDbg;
  uint8_t mAmId;
  uint8_t mIdx;
  bool mIsRoot;
  bool mForceTopology;
  bool mUart;  //is uart in use?
  bool mLocal; //was this message send local, or do our children need to see completion events
  bool mWasCommand; //is there a command that needs to be executed in dbg?
  bool mRadio; //is radio in use? (pending flag for radio)

  char mFanout;	// fanout of routing tree if forceTopology is true
  bool mCentralized; //all messages should be routed to the root (no aggregation?)
  short mMinparent; // min parent id number when we force topology
  short mMaxparent; // max parent id number when we force topology
  short mParentCand1, mParentCand2, mParentCand3;
  short mLastCheck, mLastHeard;

  uint16_t mContention; // a measure of the amount of contention on the radio -- measured via failed ACKs
  uint16_t mRem;
  enum {
    NUM_RECENT_MSGS = 8
  };

  long mRecentMsgs[NUM_RECENT_MSGS];
  uint8_t mNextMsg;

  short mRetryCnt;
  SchemaErrorNo errorNo;

  typedef enum {
    QUERY_TYPE = 0, 
    DATA_TYPE = 1
  } MsgType;

  typedef struct {
    short nodeid;
    short msgcount;
  } NodeMsgCount;

  void initHeader(DbMsgHdr *header,bool amRoot, uint8_t rootId);
  bool processHeader(DbMsgHdr header, MsgType type,uint8_t rootId);
  void setParentRange();
  void setRoot(uint8_t rootId);
  bool checkRoot(TOS_MsgPtr msg, uint8_t *rootId);
  void degradeLinkQuality(short neighborId);


  uint8_t myLevel(uint8_t rootId) {
    if (mRoots[rootId] == TOS_LOCAL_ADDRESS) return 0;
    if (mParentIx[rootId] == PARENT_UNKNOWN || mRelLevel[rootId][mParentIx[rootId]] == LEVEL_UNKNOWN)
      return LEVEL_UNKNOWN;
    return mRelLevel[rootId][mParentIx[rootId]] + 1;
  }

    command result_t StdControl.init() {
      int i;

      mSendCount = 0;
      mLastCheck = 0;
      mLastHeard = 0;
      mContention = 0;
      mRem = 0;

      mNextMsg = 0;
      for (i = 0; i < NUM_RECENT_MSGS; i++)
	mRecentMsgs[i] = 0xFFFFFFFF;

      // mark statistics invalid
      mRelOccupiedBits = 0;
      for (i = 0; i < NUM_ROOTS; i++) {
	mParentIx[i] = PARENT_UNKNOWN;
	mRoots[i] = UNKNOWN_ROOT;
      }

      mIdx = 0;
      mFanout = 0xFF; //default -- no fanout
      mCentralized = FALSE;
      mFanout = 0;
      mRadio = FALSE;
      mForceTopology = FALSE;
      mWasCommand = FALSE;
      mUart = FALSE;

      mRetryCnt = 0;
	  return call SubControl.init();
    }

    //set up data structures as though we're the root of this network
    void setRoot(uint8_t rootId) {
      //mRelOccupiedBits = 1;
      //mRelatives[0] = 0;
      //mRelLevel[rootId][0] = LEVEL_UNKNOWN;
      //mParentIx[rootId] = 0;
    }

    
    /** Given the node id of a routing tree root, determine
	the routing tree id (root parameter of data structures
	to use.
	
	Returns -1 if no more routing trees are available.
    */
    uint8_t getRootId(short rootNode) {
      int i;
      int firstUnknown = -1;

      for (i = 0; i < NUM_ROOTS; i++) {
	if (mRoots[i] != UNKNOWN_ROOT) {
	  if (mRoots[i] == rootNode) {
	    return i;
	  }
	} else if (firstUnknown == -1) {
	    firstUnknown = i;
	}
      }
      if (firstUnknown != -1) {
	mRoots[firstUnknown] = rootNode;
	return firstUnknown;
      }
	
      //HACK -- no more routing trees are available!
      return -1; //something, anyway...
    }

    //check the message to see if it sez we're supposed to be root
    //if so, set up the root and return TRUE, otherwise return FALSE
    bool checkRoot(TOS_MsgPtr msg, uint8_t *rootIdPtr) {
      short root = call QueryProcessor.msgToQueryRoot(msg);
      uint8_t rootId;

      if (root == -1) {
	*rootIdPtr = 0; //default... 
	return FALSE;
      }

      rootId = getRootId(root);
      *rootIdPtr = rootId;
      if (root == TOS_LOCAL_ADDRESS) setRoot(rootId);
      return root == TOS_LOCAL_ADDRESS;
    }
    
     command result_t StdControl.start() {
       return call SubControl.start();
     }
     
     command result_t StdControl.stop() {
       return call SubControl.stop();
     }

	command QueryResultPtr Network.getDataPayLoad(TOS_MsgPtr msg)
	{
		return (QueryResultPtr)&((NetworkMessage*)msg->data)->data[0];
	}

    /* Send a 'data' message -- data messages contain information about
   data tuples that should be sent up the routing tree.
   
   REQUIRES:  msg is a message buffer of which the first entry is of
   type DbMsgHdr

   SIGNALS: TINYDB_NETWORK_SUB_MSG_SEND_DONE after message is sent,
   unless an error is returned.

   RETURNS: err_NoError if no error
            err_UnknownError if transmission fails.
*/
     command TinyDBError Network.sendDataMessage(TOS_MsgPtr msg) {
      uint8_t rootId = 0;
      bool amRoot;

      amRoot = checkRoot(msg, &rootId);
      return call Network.sendDataMessageTo(msg, mRelatives[mParentIx[rootId]]);
    }

     //note that the "sendMessageTo" interface doesn't change the behavior of this
     // thing at all... 
     command TinyDBError Network.sendDataMessageTo(TOS_MsgPtr msg, uint16_t dest) {
      NetworkMessage *nw = (NetworkMessage *)msg->data;
      bool amRoot;
      uint8_t rootId = 0;

      mMsg = msg;
      mAmId = kDATA_MESSAGE_ID;
      

      amRoot = checkRoot(msg, &rootId);


      //send message bcast, filter at app level

      // amRoot == a base station (connected directly to the pc via the uart)
      if (!mRadio) {

	mRadio = TRUE;
	initHeader(&nw->hdr, amRoot, rootId);
	
	if (amRoot) {
	  mIdx--; //no one else will see this message -- reset the sequence counter
	  if (call SendDataMsg.send(TOS_UART_ADDR, kMSG_LEN, msg) == SUCCESS) {
	    return err_NoError;
	  } else {
	    mRadio = FALSE;
	    return err_MessageSendFailed;
	  }
	} else {
	  mRetryCnt = DATA_RETRIES;
	  if (call SendDataMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg) == SUCCESS) {
	    return err_NoError;
	  }  else {
	    mIdx--;  //failure -- reuse this index on the next try
	    mRadio = FALSE;
	    return err_MessageSendFailed;
	  }
	}
      } return err_MessageSendFailed;
     }

    command QueryMessagePtr Network.getQueryPayLoad(TOS_MsgPtr msg)
	{
		return (QueryMessagePtr)&((NetworkMessage*)msg->data)->data[0];
	}

    /* Send a 'query' message -- query messages contain information about
       queries that should be sent to neighbors in the network.
       
       REQUIRES:  msg is a message buffer of which the first entry is of
       type DbMsgHdr
       
       SIGNALS: TINYDB_NETWORK_SUB_MSG_SEND_DONE after message is sent,
       unless an error is returned.
       
       RETURNS: err_NoError if no error
       err_UnknownError if transmission fails.
    */


     command TinyDBError Network.sendQueryMessage(TOS_MsgPtr msg) {
      NetworkMessage *nw = (NetworkMessage *)msg->data;
      uint8_t rootId = 0;
      
      bool amRoot = checkRoot(msg, &rootId);

      mMsg = msg;
      mAmId = kQUERY_MESSAGE_ID;


  
      if (!mRadio) {
	mRadio = TRUE;
	initHeader(&nw->hdr, amRoot, rootId);
	mRetryCnt = QUERY_RETRIES;
	if (call SendQueryMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg) == SUCCESS) {

	  call Leds.redToggle();
	  return err_NoError;
	} else {
	  mIdx--; //failed to send -- undo counter
	  mRadio = FALSE;
	  return err_MessageSendFailed;
	}
      } 
      return err_MessageSendFailed;
      
     }


#ifdef kQUERY_SHARING
    command QueryRequestMessagePtr Network.getQueryRequestPayLoad(TOS_MsgPtr msg)
	{
		return (QueryRequestMessagePtr)&((NetworkMessage*)msg->data)->data[0];
	}

    /* Send a request for a query message to neighbors
       REQUIRES:  msg is a message buffer of which the first entry is of
       type DbMsgHdr
       
       SIGNALS: TINYDB_NETWORK_SUB_MSG_SEND_DONE after message is sent,
       unless an error is returned.
       
       RETURNS: err_NoError if no error
       err_MessageSendFailed if transmission fails.
    */
     command TinyDBError Network.sendQueryRequest(TOS_MsgPtr msg, uint16_t to) {
       NetworkMessage *nw = (NetworkMessage *)msg->data;
       uint8_t rootId = 0;
       
       bool amRoot = checkRoot(msg, &rootId);


       mMsg = msg;
       mAmId = kQUERY_REQUEST_MESSAGE_ID;
       
       if (!mRadio) {
	 mRadio = TRUE;
	 initHeader(&nw->hdr, amRoot, rootId);
	 if (call SendQueryRequest.send(to, kMSG_LEN, msg) == SUCCESS) {
	   return err_NoError;
	 }  else {
	   mRadio = FALSE;
	   return err_MessageSendFailed;
	 }
       }
       return err_MessageSendFailed;
     }
#endif
     
    /* Called when the network component has finished delivering a message. */
     result_t sendDone(TOS_MsgPtr msg, result_t success) {
       dbg(DBG_USR1,"SEND DONE \n");

       if (mUart && msg == &mDbg) { //if we finished sending a message over the uart
	 mUart = FALSE;
       } else if (mRadio) { //might not have been us that send the message!
	 mRadio = FALSE;
	if (!mLocal && !mWasCommand) { //message sent on behalf of some other component
	  switch (mAmId) {
	  case kDATA_MESSAGE_ID:
	  	signal Network.sendDataDone(msg, success);
		break;
	  case kQUERY_MESSAGE_ID:
	  	signal Network.sendQueryDone(msg, success);
		break;
	  case kQUERY_REQUEST_MESSAGE_ID:
	  	signal Network.sendQueryRequestDone(msg, success);
		break;
	  }
	} else if (mWasCommand) { //command message that has been sent, now must be executed
	  // XXX, ignore command return value for now
	  call CommandUse.invokeMsg(&mDbg, NULL, &errorNo);
	  mWasCommand = FALSE;
	} else {
	  mLocal = FALSE;
	} 
       } 
       return SUCCESS;
     }

     event result_t SendQueryMsg.sendDone(TOS_MsgPtr msg, result_t success) {
       if ((!success || !msg->ack) && mRetryCnt-- > 0) {
	 if (call SendQueryMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg) != SUCCESS) {
	   mRetryCnt = 0;
	   return sendDone(msg, FAIL);
	 }
       } else {
	 mRetryCnt = 0;
	 return sendDone(msg, success && msg->ack);
       }
       return SUCCESS;
     }

     event result_t SendDataMsg.sendDone(TOS_MsgPtr msg, result_t success) {
       uint8_t rootId = 0;       
       bool amRoot = checkRoot(msg, &rootId);

       //disabled link degredation for now -- this would be a way to work
       //around asymmetric links, but it adds a lot of instability
       //if (!msg->ack) degradeLinkQuality(((NetworkMessage *)msg->data)->hdr.parentid);

       //since root sends over uart, don't update contention since acks dont work on root
       if (!amRoot) {
	 if (!msg->ack) call NetworkMonitor.updateContention(TRUE, ACK_FAILURE);
	 else call NetworkMonitor.updateContention(FALSE,0);
       }
       if ((!success || !msg->ack) && mRetryCnt-- > 0) {
	 if (call SendDataMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg) != SUCCESS) {
	   mRetryCnt = 0;
	   return sendDone(msg, FAIL);
	 }
       } else {
	 mRetryCnt = 0;
	 return sendDone(msg, success && msg->ack);
       }
       return SUCCESS;
     }

     event result_t SendQueryRequest.sendDone(TOS_MsgPtr msg, result_t success) {
	 return sendDone(msg, success);
     }

#ifdef kSTATUS
     event result_t SendStatusMessage.sendDone(TOS_MsgPtr msg, result_t success) {
	 return sendDone(msg, success);
     }
#endif

     event result_t DebugMsg.sendDone(TOS_MsgPtr msg, result_t success) {

	 return sendDone(msg, success);
     }

     event result_t SchemaMsg.sendDone(TOS_MsgPtr msg, result_t success) {

	 return sendDone(msg, success);
     }

#ifdef kSUPPORTS_EVENTS
     event result_t EventMsg.sendDone(TOS_MsgPtr msg, result_t success) {

	 return sendDone(msg, success);
     }
#endif


     /* Check a message for CRC and to see if we've already ack'd it... 
      Return true if the messsage should be rejected.
     */
     bool filterMessage(TOS_MsgPtr msg, bool checkRecent ) {
       if (msg->crc == 0) {
	 call NetworkMonitor.updateContention(TRUE,CRC_FAILURE);
	 return TRUE;
       } else
	 call NetworkMonitor.updateContention(FALSE,0);

       if (checkRecent) {
	 NetworkMessage *nw = (NetworkMessage *)msg->data;  
	 long id = (((long)nw->hdr.senderid) << 16) + nw->hdr.idx;
	 short i;

	 if ( nw->hdr.senderid == TOS_UART_ADDR) return FALSE; //don't filter root messages

	 for (i = 0; i < NUM_RECENT_MSGS; i++) {
	     
	     if (mRecentMsgs[i] == id) {
		 return TRUE;
	     }
	 }

	 mRecentMsgs[mNextMsg++] = id;
	 
	 if (mNextMsg == NUM_RECENT_MSGS) mNextMsg = 0; //circular buffer
       }
       
       return FALSE;
     }

    /* Event that's fired when a query message arrives */
     event TOS_MsgPtr RcvQueryMsg.receive(TOS_MsgPtr msg) {
      NetworkMessage *nw = (NetworkMessage *)msg->data;  
      uint8_t rootId = 0;


      if (filterMessage(msg,TRUE)) return msg;

      checkRoot(msg, &rootId);

      if (processHeader(nw->hdr,QUERY_TYPE,rootId)) {
	//only log messages we're actually processing
	if (!mCentralized) {
	  signal Network.querySub(call Network.getQueryPayLoad(msg));
	} else {
	  //forward without processing in centralized approach
	  call Network.sendDataMessage(msg);
	}
      }

      return msg;
    }

#ifdef kQUERY_SHARING
    /* Event thats fired when a request for a query arrives from a neighbor */
     event TOS_MsgPtr RcvRequestMsg.receive(TOS_MsgPtr msg) {
      NetworkMessage *nw = (NetworkMessage *)msg->data;
      uint8_t rootId = 0;

      if (filterMessage(msg,FALSE)) return msg;

      checkRoot(msg, &rootId);


      processHeader(nw->hdr, QUERY_TYPE,rootId); //ignore return rest -- always handle these

      signal Network.queryRequestSub(call Network.getQueryRequestPayLoad(msg));

      return msg;
    }
#endif

    /* Event that's fired when a network data item arrives */
     event TOS_MsgPtr RcvDataMsg.receive(TOS_MsgPtr msg) {
      NetworkMessage *nw = (NetworkMessage *)msg->data;
      uint8_t rootId;
      bool amRoot;

      if (filterMessage(msg,TRUE)) return msg;

      amRoot = checkRoot(msg, &rootId);

      if (amRoot && nw->hdr.senderid == TOS_UART_ADDR) { //was this heartbeat from root?
	if (!mRadio /*&& !mUart*/) { 
	  mRadio = TRUE;
	  mLocal = TRUE;
	  initHeader(&nw->hdr, TRUE, rootId);
	  call Leds.redToggle();
	  if (call SendDataMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg) == FAIL) {
	    mIdx--; //reuse this index, since we failed to forward this message
	    mRadio = FALSE;
	    mLocal = FALSE;
	  }
	}
      } 


      //root sends data messages heartbeats -- ignore them
      if (processHeader(nw->hdr,DATA_TYPE,rootId) && nw->hdr.senderid != mRoots[rootId]) {
	signal Network.dataSub(call Network.getDataPayLoad(msg));
      } else if (nw->hdr.senderid != TOS_UART_ADDR) //give mote a chance to look at it even though it wasn't addressed locally
	signal Network.snoopedSub(call Network.getDataPayLoad(msg), mParentIx[rootId] != PARENT_UNKNOWN &&
				nw->hdr.senderid == mRelatives[mParentIx[rootId]], nw->hdr.senderid);
      return msg;

     }

#ifdef kSUPPORTS_EVENTS
     /** Intercept schema event messages and execute the event */
     event TOS_MsgPtr RcvEventMsg.receive(TOS_MsgPtr msg) {
       bool amRoot,shouldResend;
       uint8_t rootId;

      if (filterMessage(msg,FALSE)) return msg;

      amRoot = checkRoot(msg, &rootId);

      shouldResend = ((struct EventMsg *)(msg->data))->fromBase;

      ((struct EventMsg *)(msg->data))->fromBase = FALSE;

      if ((amRoot || shouldResend)  && !mRadio) {

	mLocal = TRUE; //don't notify higher levels about the completion of this send
	mRadio = TRUE;	
	if (call EventMsg.send(TOS_BCAST_ADDR, kMSG_LEN,  msg) != SUCCESS) {
	  mLocal = FALSE;
	  mRadio = FALSE;	
	}
      }

      call EventUse.signalEventMsg(msg);
      return msg;
    }
#endif

      /** Intercept schema command messages so that they can be forwarded from the root out
       to the rest of the nodes
    */     
    event TOS_MsgPtr RcvCommandMsg.receive(TOS_MsgPtr msg) {
      uint8_t rootId;
      bool amRoot;
      //bool shouldResend;

      if (filterMessage(msg,FALSE)) return msg;

      amRoot = checkRoot(msg, &rootId);

      //shouldResend = ((struct CommandMsg *)(msg->data))->fromBase;

      //((struct CommandMsg *)(msg->data))->fromBase = FALSE;
      //forward the message
      if ((amRoot /*|| shouldResend*/)  && !mRadio) {

	mWasCommand = TRUE; //note that we'll need to executed the command later
	mRadio = TRUE;	
	if (call SchemaMsg.send(TOS_BCAST_ADDR, kMSG_LEN,  msg) == SUCCESS) {
	  memcpy(&mDbg, msg, sizeof(TOS_Msg)); //save off command for later execution.
	} else { //failure
	  mWasCommand = FALSE;
	  mRadio = FALSE;	
	}
      } else {
	// XXX ignore command return values for now
	call Leds.greenToggle();
	call CommandUse.invokeMsg(msg, NULL, &errorNo);
      }

      return msg;
    }

#ifdef kSTATUS
    /* Event that's fired when a status request message arrives */
    event TOS_MsgPtr RcvStatusMessage.receive(TOS_MsgPtr msg) {
      short numqs,i;
      StatusMessage *smsg;

      if (filterMessage(msg,FALSE)) return msg;
      if (!mRadio) {
	smsg = (StatusMessage *)&(mDbg.data);
	mLocal = TRUE; //don't notify higher levels about the completion of this send
	mRadio = TRUE;	
	numqs = call QueryProcessor.numQueries();
	if (numqs > kMAX_QUERIES) numqs = kMAX_QUERIES;
	smsg->numQueries = numqs;
	for (i = 0; i < numqs; i++) {
	  uint8_t qid = (uint8_t)((call QueryProcessor.getQueryIdx(i))->qid);
	  dbg(DBG_USR2, "i = %d, qid = %d\n", i, qid );
	  smsg->queries[i] = qid;
	}

	if (call SendStatusMessage.send(TOS_UART_ADDR, kMSG_LEN,  &mDbg) != SUCCESS) {
	  mLocal = FALSE;
	  mRadio = FALSE;	
	}
      }

      return msg;
      
    }
#endif

    /* Maintain the local header information */
    void initHeader(DbMsgHdr *header, bool amRoot, uint8_t rootId) {
      header->senderid = TOS_LOCAL_ADDRESS;
      if (!amRoot) {
	header->parentid = mRelatives[mParentIx[rootId]];
	header->level = myLevel(rootId);
      } else {
	header->parentid = 0;
	header->level = 0;
      }
      header->idx = mIdx++;
      //if (header->idx < 0) // overflow!
      //header->idx = mIdx = 0;
      //  TOS_CALL_COMMAND(GET_TIME)(&header->sendtime);
  
    }

    // handle case where parent is unknown.
    // parent becomes the sender of this msg
    void tinydbParentInit(DbMsgHdr header, short clockCnt, uint8_t rootId) 
      {
	//  short curtime;

	mParentIx[rootId] = 0; // put parent in 1st slot in relatives array
	mRelOccupiedBits = 0x1; // 1 slot occupied: slot 0
	mRelatives[0] = header.senderid; // sender is parent
	mLastIdxRelative[0] = header.idx; 
	mCommProb[0] = 0xff; // ignore 1st message in stats
	mRelLevel[rootId][0] = header.level;
	//synchronize time with new parent (unless parent is root!)
	//	if (MY_LEVEL != 1 
	//		&& mRelatives[mParentIx] == header.senderid) {
	//	  curtime = header.sendtime + TIME_OF_FLIGHT;
	// XXXX not sure that time sync works right!
	//  TOS_CALL_COMMAND(SET_TIME)(curtime);
	//}
	dbg(DBG_USR1,"%d: parent is %d\n", TOS_LOCAL_ADDRESS, header.senderid);
      }


    // loop through all parents (for all roots) and check if the specified index is
    // a prent.
    bool isParent(uint8_t idx) {
      short i;
      for (i=0; i < NUM_ROOTS; i++) {
	if (mRoots[i] != UNKNOWN_ROOT && mParentIx[mRoots[i]] == idx)
	  return TRUE;
      }
      return FALSE;
    }


    enum {
      CONTENT_SHIFT = 4
    };
    #define MAX(a,b)((a) > (b)?(a):(b))

    command void NetworkMonitor.updateContention(bool failure, int status) {
      if (failure) {
	if (status == SEND_BUSY_FAILURE) //less severe of a failure?
	  mContention++;
	else
	  mContention += 10;
	//if (mContention < 32767 /*&& status == ACK_FAILURE*/) mContention++;
      } else {
	mContention -= (mContention >> CONTENT_SHIFT);
	if (mContention < (1 << CONTENT_SHIFT))
	  mRem += mContention;
	if (mRem > (1 << CONTENT_SHIFT)) {
	  mContention --;
	  mRem -= (1 << CONTENT_SHIFT);
	}
	//if (mContention > 0) mContention--;
      }
    }

	command uint16_t NetworkMonitor.getParent()
	{
		return mRelatives[mParentIx[0]];
	}

	command uint8_t NetworkMonitor.getDepth()
	{
		return myLevel(0);
	}

	command uint8_t NetworkMonitor.getQuality()
	{
		return mCommProb[mParentIx[0]];
	}

	command uint8_t NetworkMonitor.getQueueLength()
	{
		return 0;
	}

	command uint8_t NetworkMonitor.getMHopQueueLength()
	{
		return 0;
	}

	command uint8_t NetworkMonitor.getXmitCount()
	{
		return 0;
	}

    command uint16_t NetworkMonitor.getContention() {
      return mContention;
    }

    //make this link look less attractive, as a result of a dropped
    //message or a failed ack!
    void degradeLinkQuality(short neighborId) {
      int i;
      for (i = 0; i < NUM_RELATIVES;  i++) {
	if (mRelatives[i] == neighborId) {
	  mCommProb[i] = mCommProb[i] - (mCommProb[i] >> NACKALPHA);
	  break;
	}
      }
    }

    // loop through list of relatives looking for match to sender of msg. 
    // If match found, update stats and return index of match.  Else return BAD_IX.
    short tinydbUpdateSenderStats(DbMsgHdr header, short clockCnt, uint8_t rootId)
      {
	int i, j, numDrops;
	unsigned short oldProb;

	for (i = 0; i < NUM_RELATIVES; i++) {
	  oldProb = mCommProb[i];
	  if ((mRelOccupiedBits & (0x1 << i)) 
	      && mRelatives[i] == header.senderid) {
	    // valid match found: update stats for this relative

	    if (header.idx > mLastIdxRelative[i]) {
	      if (mLastIdxRelative[i] == 0)
		numDrops = 0;
	      else
		// the -1 is because the sender's incrementing by 1 is natural
		numDrops = (header.idx - mLastIdxRelative[i] - 1);
	    }
	    else if (mLastIdxRelative[i] >= 0x3f &&
		     header.idx < mLastIdxRelative[i] - 0x3f)
	      // hackety hack: assume wraparound if last Idx was above 128 and
	      // new idx is more than 128 lower than last
	      numDrops = (0x7f - mLastIdxRelative[i]) + header.idx;
	    else
	      // assume received out of order
	      numDrops = -1;


	    if (numDrops >= 0) {
	      if (numDrops > 0)
		dbg(DBG_USR1, "%i: node %i had %i drops\n", TOS_LOCAL_ADDRESS, mRelatives[i], numDrops);
	      // at each epoch i, our weighted moving avg a_i will be calculated
	      // (.75 * a_{i-1}) + (.25 * received)
	      // where received is 1 if we heard in that epoch, else 0
	      // We do this in integer logic in the range [0-255],
	      // so .25 ~= 63
	      for (j = 0; j < numDrops; j++)
		// subtract out 1/4 of the probability per drop
		mCommProb[i] = mCommProb[i] - (mCommProb[i] >> ALPHABITS);

	      // we heard this epoch.
	      // decrement history by a factor of 1/2^ALPHABITS.
	      mCommProb[i] -= (mCommProb[i] >> ALPHABITS);
	      // add in 2^8 * 1/(2^ALPHABITS) -1 = 2^(8-ALPHABITS) - 1
	      mCommProb[i] += (1 << (8-ALPHABITS)) - 1;
	    }
	    else {
	      // we inaccurately claimed not to receive a packet a while ago.
	      // add it back in.  It's hard to weight it appropriately, but
	      // a HACK lets decay it 1 epoch, i.e. add in 1/16 ~= 15
	      mCommProb[i] = (mCommProb[i] - (mCommProb[i] >> ALPHABITS));
	      mCommProb[i] += (1 << (8-2*ALPHABITS)) - 1;
	    }

	    mLastIdxRelative[i] = header.idx;
	    mRelLevel[rootId][i] = header.level;
	  
	    return(i);
	  } 
	}
	return(BAD_IX);
      }

    void tinydbRelativeReplace(DbMsgHdr header, short clockCnt, uint8_t rootId)
      {
	int i;
	short worst;
	unsigned char lowestProb = 255;

	// either put sender in an empty relative slot,
	// or evict worst (which requires a definition of worst)
	// 
	for (i = 0, worst = -1; i < NUM_RELATIVES; i++) {
	  if (!( mRelOccupiedBits & (0x1 << i) )) { // slot is empty, use it
	    worst = i;
	    break;
	  }
	  else { // XXX HACK: for now, always evict based on lowest commProv
	    if ((worst == -1
		 || ((mCommProb[i] < lowestProb)))
		&& (!isParent(i))) {
	      worst = i;
	      lowestProb = mCommProb[i];
	    }
	  }
	}
	mRelOccupiedBits |= (0x1 << worst);
	mRelatives[worst] = header.senderid;
	mLastIdxRelative[worst] = header.idx;
	mCommProb[worst] = 0xff; // ignore 1st message in stats
	mRelLevel[rootId][worst] = header.level;
      }

    void tinydbChooseParent(DbMsgHdr header, short clockCnt, uint8_t rootId, bool lastOk)
      {
	short i, best;
	unsigned char prob, tmpprob;
	short oldparent;
	short oldlevel;
	short any = -1, anylevel = -1;
	
	dbg(DBG_USR1,"%i: lastOk = %i, root = %i, parent = %i\n", TOS_LOCAL_ADDRESS, lastOk, rootId,
	    mRelatives[mParentIx[rootId]]);
	for (i = 0; i < NUM_RELATIVES; i++) {
	  if (mRelOccupiedBits & (0x1 << i))
	    dbg(DBG_USR1, "%i: Neighbor %i, prob = %i, level = %i\n", TOS_LOCAL_ADDRESS, mRelatives[i], mCommProb[i], mRelLevel[rootId][i]);
	}
	for (i = 0,  best = -1, prob=0; i < NUM_RELATIVES; i++) {
	  
	  //find lowest level neighbor that's not our current parent
	  //just so we have something to switch to if lastOk is false...
	  if (mRelOccupiedBits & (0x1 << i) && mParentIx[rootId] != i) {
	    if (any == -1 || mRelLevel[rootId][i] < anylevel) {
	      any = i;
	      dbg(DBG_USR1, "%i: any = %i\n", TOS_LOCAL_ADDRESS, mRelatives[any]);
	      anylevel = mRelLevel[rootId][i];
	    }
	  }

	  // HACK II: to avoid loops, don't choose a parent at a higher level than 
	  // ourselves. At our own level, can choose parents numbered higher than us

	  
	  if (mRelLevel[rootId][i] < myLevel(rootId) 
	      || (mRelLevel[rootId][i] == myLevel(rootId) && mRelatives[i] > TOS_LOCAL_ADDRESS))
	    if (mRelOccupiedBits & (0x1 << i) ) {
	      tmpprob = mCommProb[i];
	      if (tmpprob > prob) { //better level or better prob
		prob = tmpprob;
		best = i;
	      }
	    }
	}
	
	if ((lastOk || any == -1) && best == -1) return; //no good relatives to pick from...
	
	
	// HACK: choose parent based on least mean message arrival
	// set up new parent, and reset for new measurements
	//keep momentum for current parent at same level unless we see someone MUCH better
	// or new parent is at lower level than old parent
	if ((mCommProb[best] - mCommProb[mParentIx[rootId]] > MAX_PROB_THRESH
	     || mCommProb[mParentIx[rootId]] == 0)
	    || mRelLevel[rootId][best] < mRelLevel[rootId][mParentIx[rootId]]){
	  oldlevel = myLevel(rootId);
	  oldparent = mParentIx[rootId];
	  if (oldparent == best && !lastOk && any != -1) {
	    mParentIx[rootId] = any;
	  } else {
	    mParentIx[rootId] = best;
	  }

	  dbg(DBG_USR1,"%d: new parent is %d.  I was at level %d, now at level %d.  She's at level %d\n", 
	      TOS_LOCAL_ADDRESS, mRelatives[best], oldlevel,myLevel(rootId), mRelLevel[rootId][best]);
	} else {
	  if (!lastOk && any != -1) {
	    dbg(DBG_USR1, "%d: switching parents from %d to %d as a last resort.\n", TOS_LOCAL_ADDRESS,
		mRelatives[mParentIx[rootId]], mRelatives[any]);
	    mParentIx[rootId] = any;
	  }
	}



	//synchronize time with new parent (unless parent is root!)
	//  if (MY_LEVEL != 1 
	//	  && mRelatives[mParentIx] == header.senderid) 
	//	TOS_CALL_COMMAND(SET_TIME)(header.sendtime + TIME_OF_FLIGHT);
      }

    /* Do something with the header information in a message
       received from a neighbor / parent (e.g. update 
       routing tables, parent information, etc. )
       
       Return true if the message should be processed by the
       tuple router, or false if it should be rejected
    */
    bool processHeader(DbMsgHdr header,MsgType type, uint8_t rootId) 
      {
	bool wasParent = FALSE;

	if ((!mForceTopology || 
	     header.senderid == mParentCand1 ||
	     header.senderid == mParentCand2 || 
	     header.senderid == mParentCand3 ) &&
	    mRoots[rootId] != TOS_LOCAL_ADDRESS /* are we the root ? */ )
	  {
	    short clockCnt = 0;
	    short match;

	    // ignore our own messages
	    if (header.senderid == TOS_LOCAL_ADDRESS)
	      return FALSE;

	    if (mRelatives[mParentIx[rootId]] == header.senderid) {
	      //parent's level went up! -- reselect parent
	      if (header.level > mRelLevel[rootId][mParentIx[rootId]]) {
		mSendCount += PARENT_LOST_INTERVAL + 1;
	      }  else //parents level wen't down?  that's ok!
		mLastHeard = mSendCount;
	    }

	    //our parent thinks we're his parent -- bad news -- do something
	    if (header.parentid == TOS_LOCAL_ADDRESS && header.senderid == mRelatives[mParentIx[rootId]]) {
	      mSendCount += PARENT_LOST_INTERVAL + 1;
	    }

	    if (mSendCount - mLastHeard < 0)
	      mLastHeard = mSendCount; //handle wraparound

	    //HACK ! if we haven't heard from our parent for awhile, forget
	    //everything we know about our parent
		
	    if (mSendCount - mLastHeard> PARENT_LOST_INTERVAL) {
	      short parent = mParentIx[rootId];
	      mCommProb[mParentIx[rootId]] = 0; //make parent look awful
	      tinydbChooseParent(header, clockCnt,rootId, FALSE);
	      if (parent != mParentIx[rootId]) mLastHeard = mSendCount;

	      //If we pick the same parent again, this is bad news -- 
	      //we'll try to reselect parents again the next time through...
	      //We used to reset the routing state when this happened, 
	      // but resetting the routing state doesn't actually 
	      // seem to do us a lot of good :-)

	    }
			  
		  

	    //TOS_CALL_COMMAND(GET_TIME)(&clockCnt);
	    clockCnt = 0; //hack: clock unused!

	    // Base case: PARENT_UNKNOWN.  Initialize.
	    if (mParentIx[rootId] == PARENT_UNKNOWN) {
	      tinydbParentInit(header, clockCnt, rootId);

	      wasParent = TRUE; // having no parent means this node is our parent
	      mLastHeard = mSendCount;
	    }
	    else { // common case
	      //  Update stats for this sender, if known.
	      match = tinydbUpdateSenderStats(header, clockCnt,rootId);
	      if (match != BAD_IX && match == mParentIx[rootId])
		wasParent = TRUE;
	      else if (match == BAD_IX) {
		// Sender was not known.
		// Decide whether to keep track of this sender (i.e. make
		// it a "relative".)
		tinydbRelativeReplace(header, clockCnt, rootId);
	      }
		    
	      // Decide whether to change parents.
	      if (mSendCount - mLastCheck > PARENT_RESELECT_INTERVAL) {
		tinydbChooseParent(header, clockCnt, rootId,TRUE);
		mLastCheck = mSendCount;
	      }
	    }
	  }

	if (type == DATA_TYPE && header.parentid == TOS_LOCAL_ADDRESS)
	  return TRUE; //handle data messages to us
	else if (type == QUERY_TYPE) { //&& (wasParent || header.senderid == 0)) { /*}*/
	  dbg(DBG_USR1,"%d: GOT QUERY MESSAGE \n", TOS_LOCAL_ADDRESS);
	  return TRUE; 
	} 
	else
	  return FALSE;  //and nothing else
      }

    //alternate parent selection code to constrain the possible
    //set of parents we will select at any one time -- this
    //is to provide a method for fixing the network topology
    void setParentRange()
      {
	short nodes_per_level = 1;
	if (mFanout == 1)
	  {
	    mMinparent = TOS_LOCAL_ADDRESS - 1;
	    mMaxparent = TOS_LOCAL_ADDRESS - 1;
	  }
	else
	  {
	    short minparent = 0;
	    short maxparent = 0;
	    short prevminparent = minparent;
	    short prevmaxparent = maxparent;
	    //WARNING : may hang in an infinite loop if fanout < 0 !
	    while (TOS_LOCAL_ADDRESS > maxparent)
	      {
		prevminparent = minparent;
		prevmaxparent = maxparent;
		minparent = maxparent + 1;
		nodes_per_level *= mFanout;
		maxparent = minparent + nodes_per_level - 1;
	      }
	    mMinparent = prevminparent;
	    mMaxparent = prevmaxparent;
	  }
	// randomly pick three parent candidates between minparent and maxparent
	nodes_per_level = mMaxparent - mMinparent + 1;
	if (nodes_per_level <= 2)
	  {
	    mParentCand1 = mMinparent;
	    mParentCand2 = mParentCand3 = mMaxparent;
	  }
	else
	  {
	    mParentCand1 = mMinparent + call Random.rand() % nodes_per_level;
	    mParentCand2 = mMinparent + call Random.rand()  % nodes_per_level;
	    mParentCand3 = mMinparent + call Random.rand() % nodes_per_level;
	  }
      }

	event result_t CommandUse.commandDone(char *commandName, char *resultBuf, SchemaErrorNo err)
	{
		// XXX ignore command return values for now
		return SUCCESS;
	}

#ifdef kSUPPORTS_EVENTS
	event result_t EventUse.eventDone(char *name, SchemaErrorNo err) {
	  return SUCCESS;
	}
#endif

	event result_t QueryProcessor.queryComplete(ParsedQueryPtr q) {
	  return SUCCESS;
	}
}

