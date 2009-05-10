// $Id: QueryIntf.nc,v 1.3 2003/10/07 21:46:20 idgay Exp $

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

/** Interface for interacting with unparsed Queries, which represent
    queries arriving over the network that have not yet had ascii
    field names translated into schema indices.
    <p>	
    Note that most interaction with queries after network delivery is
    done via ParsedQueryPtrs and ParsedQueryIntf.
    <p>
    This interface provides basic methods to set fields and expressions
    in queries and determine if queries contain all the records needed
    to be converted into ParsedQueries.
    <p>
    @author Sam Madden (madden@cs.berkeley.edu)
*/
interface QueryIntf {
  /** @return the size (in bytes) of the specified query */
  command short size(QueryPtr q);
    
  /** @return the idx'th field from the query */
  command Field getField(QueryPtr q, uint8_t idx);

  /** @return a pointer to the idx'th field from the query */
  command Field *getFieldPtr(QueryPtr q, uint8_t idx);
    
  /**  Set the idxth field in the query to f 
   @param idx The field to set
   @param f The field ata
   @param query The query whose idxth field should be set
  */
  command result_t setField(QueryPtr q, uint8_t idx, Field f);

  /** @return the idxth expression in the query */
  command Expr getExpr(QueryPtr q, uint8_t idx);

  /** Set the idxth expression in the query 
   @param q The query to set the expression in
   @param idx The index of the expression to set
   @param e The expression data to write
  */
  command result_t setExpr(QueryPtr q, uint8_t idx, Expr e);

  /** @return TRUE iff all the fields in the query have been set */
  command bool fieldsComplete(Query q);

  /** @return TRUE iff all the expressions in the query have been set */
  command bool exprsComplete(Query q);
} 
