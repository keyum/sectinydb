// $Id: Network.nc,v 1.6 2003/10/07 21:46:20 idgay Exp $

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
includes TinyDB;

/** The network interface provides TinyDB to trap and monitor network communication --
   TupleRouter could simply be wired directly to the appropriate AM send / handlers, but
   the network monitors topology and filters events in a semi-intelligent
   way.
	<p>
   Eventually, we'd like to abstract out the parts of this that are similar to Alec's
   fancy routing from the parts that are TinyDB magic (e.g. snooped messages) 
   from the parts that really are just wrappers around other components (e.g. setPot).
<p>
   Implemented by NetworkC.td.

@author Sam Madden (madden@cs.berkeley.edu), Wei Hong (whong@intel-reseach.net)
*/

interface Network {
  /**
   * Typically called before sendDataMessage, this command allows
   * the caller to identify the payload portion of the data message.
   * @param msg A pointer to the tos message buffer.
   * @param len A pointer to a length byte.  On return, it will be set to
   *			the maximum length of the payload area.
   * @return A pointer to the start of the payload area.
   */
  command QueryResultPtr getDataPayLoad(TOS_MsgPtr msg);

  /** Send out a message containing a tuple, using the multihop forwarding protocol
      of choice to reach the parent node.
	@param msg The message to send
	@return err_MsgSendFailed if message failed to xmit 
  */
  command TinyDBError sendDataMessage(TOS_MsgPtr msg);

  /** Send out a message containing a tuple to the specified address
      @param msg The message to send
      @param to The address to send it to (or TOS_BCAST_ADDR)
      @return err_MsgSendFailed if the message failed to xmit.
  */
  command TinyDBError sendDataMessageTo(TOS_MsgPtr msg, uint16_t to);

  /** Signalled when a data message has been sent 
   * @param msg The message that was sent
   * @param success SUCCESS if the send succeeded, FAIL otherwise
   * @return SUCCESS, but ignored
  */
  event result_t sendDataDone(TOS_MsgPtr msg, result_t success);
    
#ifdef kQUERY_SHARING
  /**
   * Typically called before sendQueryRequest, this command allows
   * the caller to identify the payload portion of the query request message.
   * @param msg A pointer to the tos message buffer.
   * @param len A pointer to a length byte.  On return, it will be set to
   *			the maximum length of the payload area.
   * @return A pointer to the start of the payload area.
   */
  command QueryRequestMessagePtr getQueryRequestPayLoad(TOS_MsgPtr msg);

  /** Send out a message requesting a neighbor describe a query
	@param msg The message to send
	@param to the destination mote id
	@return err_MsgSendFailed if message failed to xmit 
  */
  command TinyDBError sendQueryRequest(TOS_MsgPtr msg, uint16_t to);
    
  /** Signalled when a query request message has been sent 
   * @param msg The message that was sent
   * @param success SUCCESS if the send succeeded, FAIL otherwise
   * @return SUCCESS, but ignored
  */
  event result_t sendQueryRequestDone(TOS_MsgPtr msg, result_t success);
#endif
    
  /**
   * Typically called before sendQueryMessage, this command allows
   * the caller to identify the payload portion of the query message.
   * @param msg A pointer to the tos message buffer.
   * @param len A pointer to a length byte.  On return, it will be set to
   *			the maximum length of the payload area.
   * @return A pointer to the start of the payload area.
   */
  command QueryMessagePtr getQueryPayLoad(TOS_MsgPtr msg);

  /** broadcast a message containing part of a query to the neighbors
    after one of them requested the query
	@param msg The message to send
	@return err_MsgSendFailed if message failed to xmit 
  */
  command TinyDBError sendQueryMessage(TOS_MsgPtr msg);
    
  /** Signalled when a query message has been sent 
   * @param msg The message that was sent
   * @param success SUCCESS if the send succeeded, FAIL otherwise
   * @return SUCCESS, but ignored
  */
  event result_t sendQueryDone(TOS_MsgPtr msg, result_t success);
    
  /** Signalled when a data (tuple) message is received from a neighbor 
   * @param The data message that was received. Owned by the caller.
   * @return SUCCESS, ignored
   */
  event result_t dataSub(QueryResultPtr qresMsg);
    
  /** Signalled when a query message is received from a broadcast
   @param msg The query message that was received.  Owned by the caller. 
   @return SUCCESS, ignored
  */
  event result_t querySub(QueryMessagePtr qMsg);
    
  /** Signalled when a message not directed to us is heard (snooped) 
   @param msg a data message is heard from a neighbor.  Owned by the caller.
   @param isFromParent set to TRUE if the message was sent by the parent
   @param senderid is the node id of the message sender
   @return SUCCESS, ignored
  */
  event result_t snoopedSub(QueryResultPtr qresMsg, bool isFromParent, uint16_t senderid);

#ifdef kQUERY_SHARING
  /** Signalled when a neighbor mote requests a query from us 
   * @param The message our neighbor sent.  Owned by the caller.
   * @return SUCCESS, ignored
  */
  event result_t queryRequestSub(QueryRequestMessagePtr qreqMsg);
#endif
}
