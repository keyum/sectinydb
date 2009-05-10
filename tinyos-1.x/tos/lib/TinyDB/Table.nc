// $Id: Table.nc,v 1.3 2003/10/07 21:46:21 idgay Exp $

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

/**	
	The Table interface keeps track of schemas with named
	fields.  Tables are used to represent buffers (e.g. materialization points),
	or track aliases for fields (or aggregate fields) in queries.

	@author Sam Madden (madden@cs.berkeley.edu)
*/	
interface Table {
  command result_t addNamedField(ParsedQuery *pq, uint8_t idx, char *name, uint8_t type);
  command result_t getType(ParsedQuery *pq, uint8_t fieldIdx, uint8_t *type);
  command result_t getNamedField(ParsedQuery *pq, char *field, uint8_t *fieldId);
  command result_t getFieldName(ParsedQuery *pq, uint8_t idx, char **name);
  command bool hasNamedFields(ParsedQuery *pq);
  event result_t addNamedFieldDone(result_t success);
}

