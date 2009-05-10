// $Id: AggregateUse.nc,v 1.6 2003/10/07 21:46:22 idgay Exp $

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
 * Intention is to make addition of user-defined aggregates easy.
 * Dispatch is based on aggregate id (AggregateID enum is Aggregates.h),
 * which is the first argument for every command in this interface.
 * No in-memory data structures is created to keep aggregate info, therefore
 * we need to pass ParamList argument to each command
 * @author Eugene Shvets
 */

includes Aggregates;
interface AggregateUse {
  /**
   * dest, merge - raw data. each aggregate can cast it to appropriate data structure.
   * Stuff that previosly came as part of expr->ex.tagg is passed in general way as list of params
   */
  command result_t merge(uint8_t id, char *destdata, char *mergedata, ParamList *params, ParamVals *paramValues);

  //we'll probably get rid of this later
  command result_t update(uint8_t id, char *dest, char* value, ParamList *params, ParamVals *paramValues);

  /**
   * Called in the beginning of each epoch
   * @param isFirstTime true if this is the very first call for this aggregate
   */
  command result_t init(uint8_t id, char *data, ParamList *params, ParamVals *paramValues, bool isFirstTime);

  command uint16_t stateSize(uint8_t id, ParamList *params, ParamVals *paramValues);

  command bool hasData(uint8_t id, char *data, ParamList *params, ParamVals *paramValues);

  command TinyDBError finalize(uint8_t id, char *data, char *result_buf, ParamList *params, ParamVals *paramValues);
  
  command AggregateProperties getProperties(uint8_t id);
}
