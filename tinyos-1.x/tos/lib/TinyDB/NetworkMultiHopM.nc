// $Id: NetworkMultiHopM.nc,v 1.17 2004/04/12 16:51:32 idgay Exp $

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
 * Author:	Wei Hong
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

   The routing in this module will be based on the standard interfaces
   Send, Receive, Intercept and Bcast.
*/

/**
 * @author Wei Hong
 */


includes TinyDB;
// includes TosTime; 
module NetworkMultiHopM {

  provides {
    interface Network;
    interface StdControl;
    interface NetworkMonitor;
  }

  uses {
    interface Send;
	interface Intercept;
	interface Intercept as Snoop;
	interface MultiHopMonitor;
	interface StdControl as MultiHopStdControl;
	interface RouteControl as MultiHopControl;
    interface SendMsg as SendQueryMsg;
    interface SendMsg as SendDataMsg;
    interface SendMsg as SendStatusMsg;
    interface SendMsg as SendQueryRequest;
    interface SendMsg as SendCommandMsg;

    interface ReceiveMsg as RcvQueryMsg;
    interface ReceiveMsg as RcvDataMsg;
#ifdef kQUERY_SHARING
    interface ReceiveMsg as RcvRequestMsg;
#endif
    interface ReceiveMsg as RcvCommandMsg;
#ifdef kSUPPORTS_EVENTS
    interface ReceiveMsg as RcvEventMsg;


    interface SendMsg as SendEventMsg;
#endif
#ifdef kSTATUS
    interface ReceiveMsg as RcvStatusMessage;
#endif

    interface CommandUse;
#ifdef kSUPPORTS_EVENTS
    interface EventUse;
#endif
#ifdef kSTATUS
	interface QueryProcessor;
#endif
    interface Leds;
	/*
    interface ReceiveMsg as RcvRTCTime;
    interface Time;
	*/
	interface QueueControl;
#ifdef USE_WATCHDOG
	interface StdControl as PoochHandler;
	interface WDT;
#endif
	interface Timer as DelayTimerA;
	interface Timer as DelayTimerB;
	interface Random;
  }
}
implementation 
{
	TOS_Msg mDbg;
	bool mWasCommand;
	uint8_t mLastSeqNo;
#ifdef kHAS_NEIGHBOR_ATTR     
	uint32_t mNeighborsLo;
	uint32_t mNeighborsHi;
#endif
	TOS_MsgPtr gpSendDataMessage;
	TOS_MsgPtr gpSendDataMsgTo;
	uint16_t gTo;

	void updateNeighbors(TOS_MsgPtr);

	enum {
	  MAX_MISSED_CMDS = 8
	};

	command result_t StdControl.init() 
	{
		mWasCommand = FALSE;
		mLastSeqNo = 0;
#ifdef kHAS_NEIGHBOR_ATTR
		mNeighborsLo = mNeighborsHi = 0;
#endif
#ifdef USE_WATCHDOG
		call PoochHandler.init();
#endif
		return call MultiHopStdControl.init();
	}

    command result_t StdControl.start() 
	{
#ifdef USE_WATCHDOG
		// call PoochHandler.start();
		// call WDT.start((int32_t)60000L); // every minute, baby ...
#endif
		return call MultiHopStdControl.start();
    }
     
    command result_t StdControl.stop() 
	{
		return call MultiHopStdControl.stop();
    }

	command QueryResultPtr Network.getDataPayLoad(TOS_MsgPtr msg)
	{
		uint16_t len;
		return (QueryResultPtr)call Send.getBuffer(msg, &len);
	}

	event result_t DelayTimerA.fired() 
	{
		return call Send.send(gpSendDataMessage, sizeof(QueryResult));
	}

	event result_t DelayTimerB.fired()
	{
		return call SendDataMsg.send(gTo, kMSG_LEN, gpSendDataMsgTo);
	}

	command TinyDBError Network.sendDataMessage(TOS_MsgPtr msg) 
	{
	  //HACK -- stealing state from lower network layer

#if 0
		if (call Send.send(msg, sizeof(QueryResult)) == FAIL)
			return err_MessageSendFailed;
#else
		gpSendDataMessage = msg;
		call DelayTimerA.start(TIMER_ONE_SHOT, (call Random.rand()) & 0xff);
#endif

		return err_NoError;
	}

	command TinyDBError Network.sendDataMessageTo(TOS_MsgPtr msg, uint16_t to) 
	{
	  TOS_MHopMsg *mh = (TOS_MHopMsg *)msg->data;
	  mh->sourceaddr = mh->originaddr = TOS_LOCAL_ADDRESS;
	  mh->seqno = 0;
	  mh->hopcount = 0;

#if 0
	  if (call SendDataMsg.send(to, kMSG_LEN, msg) == FAIL)
	    return err_MessageSendFailed;
	  //call Leds.redToggle();
#else
	  gTo = to;
	  gpSendDataMsgTo = msg;
	  call DelayTimerB.start(TIMER_ONE_SHOT, (call Random.rand()) & 0xff);
#endif
	  return err_NoError;
	}


	event result_t Send.sendDone(TOS_MsgPtr msg, result_t success)
	  {
	    if (success == SUCCESS) call Leds.redToggle();
	    signal Network.sendDataDone(msg, success);
	    return SUCCESS;
	  }

	command QueryMessagePtr Network.getQueryPayLoad(TOS_MsgPtr msg)
	{
		return (QueryMessagePtr)msg->data;
	}

    command TinyDBError Network.sendQueryMessage(TOS_MsgPtr msg) 
	{
		QueryMessagePtr qmsg = call Network.getQueryPayLoad(msg);
		qmsg->fwdNode = TOS_LOCAL_ADDRESS; // purely for debugging
		if (call SendQueryMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg) == SUCCESS) 
		{
		  call Leds.greenToggle();
			return err_NoError;
		} 
		return err_MessageSendFailed;
    }

#ifdef kQUERY_SHARING
	command QueryRequestMessagePtr Network.getQueryRequestPayLoad(TOS_MsgPtr msg)
	{
		return (QueryRequestMessagePtr)msg->data;
	}

	command TinyDBError Network.sendQueryRequest(TOS_MsgPtr msg, uint16_t to)
	  {

		QueryRequestMessagePtr qreqMsg = call Network.getQueryRequestPayLoad(msg);
		qreqMsg->reqNode = TOS_LOCAL_ADDRESS;
		qreqMsg->fromNode = to;
	    if (call SendQueryRequest.send(to, kMSG_LEN, msg) == SUCCESS) 
	      {
		return err_NoError;
	      }  
	    return err_MessageSendFailed;
	}
#endif
     
	event result_t SendQueryMsg.sendDone(TOS_MsgPtr msg, result_t success) 
	{
		signal Network.sendQueryDone(msg, success);
		return SUCCESS;
	}

	event result_t SendCommandMsg.sendDone(TOS_MsgPtr msg, result_t success)
	{
		if (mWasCommand)
		{
			SchemaErrorNo errorNo;
			// XXX ignore command return value for now
			call CommandUse.invokeMsg(&mDbg, NULL, &errorNo);
			mWasCommand = FALSE;
		}
		return SUCCESS;
	}

#ifdef kSUPPORTS_EVENTS
	event result_t SendEventMsg.sendDone(TOS_MsgPtr msg, result_t success)
	{
		return SUCCESS;
	}
#endif

    event result_t SendQueryRequest.sendDone(TOS_MsgPtr msg, result_t success) 
	{
		signal Network.sendQueryRequestDone(msg, success);
		return SUCCESS;
    }

    event result_t SendDataMsg.sendDone(TOS_MsgPtr msg, result_t success) 
	{
	  signal Network.sendDataDone(msg,success);
	  return SUCCESS;
	}

    event result_t SendStatusMsg.sendDone(TOS_MsgPtr msg, result_t success) 
	{
		return SUCCESS;
	}

    /* Event that's fired when a query message arrives */
	event TOS_MsgPtr RcvQueryMsg.receive(TOS_MsgPtr msg) 
	{
		QueryMessagePtr qMsg = call Network.getQueryPayLoad(msg);
		signal Network.querySub(qMsg);
		return msg;
    }

#ifdef kQUERY_SHARING
    /* Event thats fired when a request for a query arrives from a neighbor */
	event TOS_MsgPtr RcvRequestMsg.receive(TOS_MsgPtr msg) 
	{
		QueryRequestMessagePtr qreqMsg = call Network.getQueryRequestPayLoad(msg);
		if (msg->addr == TOS_LOCAL_ADDRESS)
			signal Network.queryRequestSub(qreqMsg);
		return msg;
	}
#endif

	event result_t Intercept.intercept(TOS_MsgPtr msg, void* payload, uint16_t payloadLen) 
	{
		QueryResultPtr qr = (QueryResultPtr)payload;
		TOS_MHopMsg *mh = (TOS_MHopMsg *)msg->data;
		uint16_t sender = mh->sourceaddr;
#ifdef USE_WATCHDOG
		call WDT.reset();
#endif
		call Leds.greenToggle();

		updateNeighbors(msg);
		if (call QueryProcessor.queryProcessorWantsData(qr)) {
		  signal Network.dataSub(qr);
		  return FAIL; // do not forward the message, TinyDB will resend
		} else {
		  signal Network.snoopedSub(qr, FALSE, sender);
		  return SUCCESS;
		}

	}

	event result_t Snoop.intercept(TOS_MsgPtr msg, void* payload, uint16_t payloadLen)
	{
		QueryResultPtr qr = (QueryResultPtr)payload;
		TOS_MHopMsg *mh = (TOS_MHopMsg *)msg->data;
		uint16_t sender = mh->sourceaddr;
		bool isParent = (call NetworkMonitor.getParent() == mh->originaddr) && (mh->originaddr == mh->sourceaddr);
		//if (call MultiHopControl.getParent() == TOS_UART_ADDR) // if this is root
		//	return SUCCESS;

		signal Network.snoopedSub(qr, isParent, sender);
		// forward all query results the root overhears to UART before
		// its immediate neighbors choose a parent.
		// this solves the unbearably long initial delay
		// in MH6.
#ifdef USE_WATCHDOG
		call WDT.reset();
#endif
		updateNeighbors(msg);

		if (isRoot() && mh->hopcount == 0xFF)
		{
		  dbg(DBG_USR1, "UNTARGETED MESSAGE FROM %d, SEQNO %d\n", mh->originaddr, mh->seqno);
		  signal Network.dataSub(qr);
		  return FAIL; // do not forward the message, TinyDB will resend
		}

		return SUCCESS;
	}

#ifdef kSUPPORTS_EVENTS
     /** Intercept schema event messages and execute the event */
	event TOS_MsgPtr RcvEventMsg.receive(TOS_MsgPtr msg) 
	{

		bool shouldResend;

		shouldResend = ((struct EventMsg*)(msg->data))->fromBase;
		((struct EventMsg*)(msg->data))->fromBase = FALSE;

		if (shouldResend)
		  {
		    
		    call SendEventMsg.send(TOS_BCAST_ADDR, kMSG_LEN, msg);
		}

		call EventUse.signalEventMsg(msg);
		return msg;
    }
#endif
#if 0
    /** Receive a RTCTime msg */
    event TOS_MsgPtr RcvRTCTime.receive(TOS_MsgPtr msg)
    {
          tos_time_t tt;
          struct RTCMsg * p =(struct RTCMsg *)(msg ->data);
          tt.high32 =p.time_high;
          tt.low32 = p.time_low32;
          call Time.set(tt);
          return msg;
    }
#endif

      /** Intercept schema command messages so that they can be forwarded from the root out
       to the rest of the nodes
    */     
	event TOS_MsgPtr RcvCommandMsg.receive(TOS_MsgPtr msg) 
	{
		bool isNew;
		struct CommandMsg *cm = (struct CommandMsg *)msg->data;

		//just look at low bits of sequence number
		uint8_t seqno = (uint8_t)(cm->seqNo);
		
		call Leds.redToggle();
		isNew = (seqno > mLastSeqNo) || 
		  (abs((int16_t)seqno - (int16_t)mLastSeqNo) > MAX_MISSED_CMDS);		
		
		if (isNew)
		{
		  mLastSeqNo = seqno;
		  mWasCommand = TRUE;		  
		  call Leds.greenToggle();
		  mDbg = *msg;

		  if (call SendCommandMsg.send(TOS_BCAST_ADDR, kMSG_LEN, &mDbg) != SUCCESS) {
		    SchemaErrorNo errorNo;
		    
		    call CommandUse.invokeMsg(&mDbg, NULL, &errorNo);
		    mWasCommand = FALSE;
		  }
		}

		return msg;
    }

#ifdef kSTATUS
    /* Event that's fired when a status request message arrives */
    event TOS_MsgPtr RcvStatusMessage.receive(TOS_MsgPtr msg) 
	{
		if (((StatusMessage*)msg->data)->fromBase)
		{
			short numqs, i;
			StatusMessage *smsg;

			smsg = (StatusMessage *)&(mDbg.data);
			smsg->fromBase = FALSE;
			numqs = call QueryProcessor.numQueries();
			if (numqs > kMAX_QUERIES) 
				numqs = kMAX_QUERIES;
			smsg->numQueries = numqs;
			for (i = 0; i < numqs; i++) 
			{
				uint8_t qid = (uint8_t)((call QueryProcessor.getQueryIdx(i))->qid);
				dbg(DBG_USR2, "i = %d, qid = %d\n", i, qid );
				smsg->queries[i] = qid;
			}
			if (call MultiHopControl.getParent() == TOS_UART_ADDR) // if this is root
			  call SendStatusMsg.send(TOS_UART_ADDR, kMSG_LEN, &mDbg);
			else
			  call SendStatusMsg.send(TOS_BCAST_ADDR, kMSG_LEN, &mDbg);
		}
		return msg;
    }
#endif

    event TOS_MsgPtr RcvDataMsg.receive(TOS_MsgPtr msg) {
      uint16_t len;
      void *payload = call Send.getBuffer(msg, &len);
      
      signal Snoop.intercept(msg, payload, len) ;
      return msg;
    }

    command uint16_t NetworkMonitor.getContention() 
	{
		// XXX temporarily disabled
		return 0;
    }

    command void NetworkMonitor.updateContention(bool failure, int status) 
	{
		// XXX temporarily disabled
    }

	command uint16_t NetworkMonitor.getParent()
	{
		return call MultiHopControl.getParent();
	}

	command uint8_t NetworkMonitor.getQueueLength()
	{
		return call QueueControl.getOccupancy();
	}

	command uint8_t NetworkMonitor.getXmitCount()
	{
		return call QueueControl.getXmitCount();
	}

	command uint8_t NetworkMonitor.getQuality()
	{
		return call MultiHopControl.getQuality();
	}
	command uint8_t NetworkMonitor.getDepth()
	{
		return call MultiHopControl.getDepth();
	}

	command uint8_t NetworkMonitor.getMHopQueueLength()
	{
		return call MultiHopControl.getOccupancy();
	}

#ifdef kHAS_NEIGHBOR_ATTR
	/** Write the list of neighbors we have recently heard into
	    the bitmap dest.  Bit n in the bitmap corresponds to a recent
	    message from sensor n
	*/
	command void NetworkMonitor.getNeighbors(char *dest) {
	  memcpy(dest, (char*)&mNeighborsLo, sizeof(uint32_t));
	  memcpy(dest+4, (char*)&mNeighborsHi, sizeof(uint32_t));
	  // *(uint32_t *)dest = mNeighborsLo;
	  // *(uint32_t *)(&dest[4]) = mNeighborsHi;
	    
	  //clear after read
	  mNeighborsLo = 0;
	  mNeighborsHi = 0;
	}
#endif

	void updateNeighbors(TOS_MsgPtr msg) {
#ifdef kHAS_NEIGHBOR_ATTR
	  TOS_MHopMsg *mh = (TOS_MHopMsg *)msg->data;
	  uint32_t sender = mh->sourceaddr; //not originaddr!
	  // ignore forwarded packets
	  if (mh->sourceaddr != mh->originaddr)
	  	return;

	  if (sender < 32)
	    mNeighborsLo |= (1L << sender);
	  else if (sender < 64)
	    mNeighborsHi |= (1L << (sender - 32));
	  //	  dbg(DBG_USR1, "heard message from : %d, lo = %d, hi = %d\n", sender, mNeighborsLo, mNeighborsHi);
#endif
	}

#ifdef kSUPPORTS_EVENTS
	event result_t EventUse.eventDone(char *name, SchemaErrorNo err) 
	{
		return SUCCESS;
	}
#endif
	event result_t CommandUse.commandDone(char *commandName, char *resultBuf, SchemaErrorNo err)
	{
		return SUCCESS;
	}

	event result_t QueryProcessor.queryComplete(ParsedQueryPtr q)
	{
		return SUCCESS;
	}
}
