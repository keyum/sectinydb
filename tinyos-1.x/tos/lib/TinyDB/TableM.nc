// $Id: TableM.nc,v 1.3 2003/10/07 21:46:21 idgay Exp $

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
module TableM {
  provides {
    interface Table;
    interface StdControl;
  }

  uses {
    interface MemAlloc;
#ifdef kUART_DEBUGGER
    interface Debugger as UartDebugger;
#endif
  }
}

implementation {
  uint8_t mIdx;
  char *mName;
  uint8_t mType;
  ParsedQuery *mQuery;
  bool mAllocing;

  uint8_t nameSize(char *names, uint8_t i);
  uint8_t *getTypes(ParsedQuery *pq);
  char *getAliases(ParsedQuery *pq);
  uint8_t nameOffset(char *names, uint8_t i);
	
  command result_t StdControl.init() {
    mAllocing = FALSE;
    mQuery = NULL;

    return SUCCESS;
  }
  
  command result_t StdControl.start() {
    return SUCCESS;
  }

  command result_t StdControl.stop() {
    return SUCCESS;
  }
  
  /** 
   * Add the specified named field (with the specified type) to the auxiliary table
   * info stored in the query.  Idx is the index of the field in the table.
   * If a field with this index already exists it will be overwritten.
   * If index is greater than pq->numField, will return FAIL.
   * If an allocation is already pending, will return FAIL.
   *
   * Split phase operation, with completion signalled via addNamedFieldDone() event
   * Name and pq must not be allocated on caller's stack 
   */
  command result_t Table.addNamedField(ParsedQuery *pq, uint8_t idx, char *name, uint8_t type) {
    
    if (mAllocing) return FAIL;
    mAllocing = TRUE;

    mName = name;
    mType = type;
    mIdx = idx;
    mQuery = pq;

    if (pq->tableInfo == NULL) {
      //(one byte per type, one byte per string)
      return call MemAlloc.allocate((Handle *)&pq->tableInfo, pq->numFields * 2 + strlen(name));
    } else {
      //need to make it length of name bytes longer
      int size = call MemAlloc.size((Handle)pq->tableInfo);
      size += strlen(name);
      size -= nameSize(getAliases(pq), idx) - 1;
      return call MemAlloc.reallocate((Handle)pq->tableInfo, size);
    }
  }

  // Return the types array from the tableInfo structure
  // DOES NOT CHECK FOR NULL
  uint8_t *getTypes(ParsedQuery *pq) {
    return (uint8_t *)((*pq->tableInfo));
  }

  // Return the aliases array from the tableInfo structure
  // DOES NOT CHECK FOR NULL
  char *getAliases(ParsedQuery *pq) {
    return ((char *)(*pq->tableInfo) + pq->numFields);
  }

  /* Check and see if there is any field name information 
     in the parsed query 
  */
  command bool Table.hasNamedFields(ParsedQuery *pq) {
    return pq->tableInfo != NULL;
  }

  /** Return the type of the specified field in the table,
      if the table has named fields.
      If the index is invalid, or the field doesn't exist, return NULL.
  */
  char typestr[5];

  command result_t Table.getType(ParsedQuery *pq, uint8_t fieldIdx, uint8_t *type) {
    if (pq->tableInfo != NULL && pq->numFields > fieldIdx) {
      *type = getTypes(pq)[fieldIdx];

      return SUCCESS;
    }
    return FAIL;
  }

  /**
     Return the field index which corresponds to ths specified named field.
     If no such field exists, return FAIL.
   */
  command result_t Table.getNamedField(ParsedQuery *pq, char *field, uint8_t *fieldId) {
    int i = 0;
    char *names;

    if (pq->tableInfo == NULL) return FAIL;
    names = getAliases(pq);

    for (i = 0; i < pq->numFields; i++) {
      if (strcmp(field, &names[nameOffset(names, i)]) == 0) {
	*fieldId = i;
	return SUCCESS;
      }
    }

    return FAIL;
  }
  
  /** Given an index into the fields array, return the name which corresponds to the
      specified field.  If no such field exists, return FAIL.
  */
  command result_t Table.getFieldName(ParsedQuery *pq, uint8_t idx, char **name) {
    char *names;
    if (pq->tableInfo != NULL && pq->numFields > idx) {
      names = getAliases(pq);
      *name = &names[nameOffset(names, idx)];
      return SUCCESS;
    }
    return FAIL;
  }

  /** Completion task which is called after a field gets added */
  task void addField() {
    char *names =  getAliases(mQuery);
    strcpy(&names[nameOffset(names, mIdx)], mName); 
    getTypes(mQuery)[mIdx] = mType;


    mQuery = NULL;
    mAllocing = FALSE;
    signal Table.addNamedFieldDone(SUCCESS);
  }
  
  event result_t MemAlloc.allocComplete(HandlePtr handle, result_t success) {
    if (mQuery != NULL && handle == (HandlePtr)&mQuery->tableInfo) {
      if (success == SUCCESS) {
	memset(getAliases(mQuery), (char)0, mQuery->numFields);
	post addField();
      }
      else {
	mAllocing = FALSE;
	mQuery = NULL;
	signal Table.addNamedFieldDone(success);
      }
    }
    return SUCCESS;
  }

  //return the offset into the names string of the ith name
  uint8_t nameOffset(char *names, uint8_t i) {
    uint8_t offset = 0;
    while (i--) { //find the start of the ith string
      while (names[offset] != 0) offset++; //look for null-term
      offset++; //and skip it
    }
    return offset;
  }
  
  //return the size of the ith name (including the null term)
  uint8_t nameSize(char *names, uint8_t i) {
    uint8_t size = 0, pos = 0;
    int len = i;
    while (len-- >= 0) { //find the length of the ith string
      size = 0; //reset size on every string
      while (names[pos++] != 0) size++; //look for null-term
      size++; //and count it
    }
    return size;

  }

  
  uint8_t totalNameSize(ParsedQuery *pq) {
    return (call MemAlloc.size((Handle)pq->tableInfo) - pq->numFields);
  }
  
  
  event result_t MemAlloc.reallocComplete(Handle handle, result_t success) {
    if (mQuery != NULL && handle == (Handle)mQuery->tableInfo) {      
      if (success == SUCCESS) {
	char *names = getAliases(mQuery);
	//need to move down bytes to make space for
	//new field
	if (mIdx + 1 < mQuery->numFields) {
	  memcpy(&names[nameOffset(names, mIdx+1) + (strlen(mName) + 1) - nameSize(names, mIdx)],
		 &names[nameOffset(names, mIdx+1)],	
		 totalNameSize(mQuery) - nameOffset(names,mIdx+1));  
	}
	post addField();
      }
      else {
	mAllocing = FALSE;
	mQuery = NULL;
	signal Table.addNamedFieldDone(success);
      }
    }
    return SUCCESS;
  }

  event result_t MemAlloc.compactComplete() {
    return SUCCESS;
  }

#ifdef kUART_DEBUGGER
  async event result_t  UartDebugger.writeDone(char * string, result_t success) {
    return SUCCESS;
  }
#endif
  
    
}
