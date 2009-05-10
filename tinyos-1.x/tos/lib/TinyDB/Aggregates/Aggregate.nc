// $Id: Aggregate.nc,v 1.5 2003/10/07 21:46:21 idgay Exp $

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
 * Author: Eugene Shvets
 *
 * This interface allows users to create custom aggregates. All built-in
 * aggregates conform to this interface.
 * @author Eugene Shvets
 */

interface Aggregate {

  /**
   * Updates local partial state with another partial state
   */
  command result_t merge(char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues);
  
  /**
   * Updates local state with a sensor reading
   */
  command result_t update(char *dest, char* value, ParamList *params, ParamVals *paramValues);

  /**
   * Initializer
   * Called in the beginning of each epoch
   * @param isFirstTime true if this is the very first call for this aggregate
   */
  command result_t init(char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime);
  
  /**
   * Finalizer
   */
  command TinyDBError finalize(char *data, char *result_buf, ParamList *params, ParamVals *paramValues);

  /**
   * Returns the size of aggregate's state, in bytes
   */
  command uint16_t stateSize(ParamList *params, ParamVals *paramValues);

  /**
   * Called each epoch, returns true if aggregate has data to send out
   */
  command bool hasData(char *data, ParamList *params, ParamVals *paramValues);
  
  /**
   * Returns aggregate properties, such as monotonic, etc
   */
   
   command AggregateProperties getProperties();
}
