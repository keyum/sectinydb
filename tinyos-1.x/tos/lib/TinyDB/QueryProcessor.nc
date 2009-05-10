// $Id: QueryProcessor.nc,v 1.5 2003/10/07 21:46:20 idgay Exp $

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

/** A QueryProcessor runs queries -- this interface is very simple since
    our only query processor (TupleRouterM) generates and processes queries
    all by itself (it doesn't currently provide a non-am based interface
    for receiving queries from neighbors.)
    <p>
    See uses portion of the Network interface in  TupleRouterM to understand
    how queries are submitted to a query processor.
    <p>
    For now, this interface simply allows clients to know when a query has ended
    and get information about currently running queries.
    @author Sam Madden (madden@cs.berkeley.edu)
*/
    
    
interface QueryProcessor {
  /** Signalled when a query ends
      @param q The query that ended
  */
  event result_t queryComplete(ParsedQueryPtr q);

  /** Return information about a currently running query
      @param qid The query for which information is sought
      @return A pointer to the query data structure, or NULL if no such query exists.
  */
  command ParsedQueryPtr getQueryCmd(uint8_t qid);

  /** Given a processor message return the owner (origninating node) of the query, or
      -1 if the query is unknown or the message is a query processor message.

      @param msg The query for which the root is sought
  */
  command short msgToQueryRoot(TOS_Msg *msg);

  command short numQueries();
  command ParsedQueryPtr getQueryIdx(short i);

  command bool queryProcessorWantsData(QueryResult *qr);

}
