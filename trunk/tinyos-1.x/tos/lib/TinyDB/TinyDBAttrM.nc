// $Id: TinyDBAttrM.nc,v 1.6 2004/03/26 17:20:43 whong Exp $

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

module TinyDBAttrM 
{
	provides interface StdControl;
	uses
	{
		interface AttrRegister as ParentAttr;
#ifdef kCONTENT_ATTR
		interface AttrRegister as ContentionAttr;
#endif
		interface AttrRegister as FreeSpaceAttr;
#ifdef kQUEUE_LEN_ATTR
		interface AttrRegister as QueueLenAttr;
#endif
#ifdef kMHQUEUE_LEN_ATTR
		interface AttrRegister as MHQueueLenAttr;
#endif
		interface AttrRegister as DepthAttr;
		interface AttrRegister as QidAttr;
		// interface AttrRegister as XmitCountAttr;
		interface AttrRegister as QualityAttr;
#ifdef kHAS_NEIGHBOR_ATTR
		interface AttrRegister as NeighborAttr;
#endif
		interface NetworkMonitor;
		interface QueryProcessor;
		interface MemAlloc;
	}
}
implementation 
{
	command result_t StdControl.init()
	{
		call ParentAttr.registerAttr("parent", UINT16, 2);
#ifdef kCONTENT_ATTR
		call ContentionAttr.registerAttr("content", UINT16, 2);
#endif
		call FreeSpaceAttr.registerAttr("freeRAM", UINT16, 2);
#ifdef kQUEUE_LEN_ATTR
		call QueueLenAttr.registerAttr("qlen", UINT8, 1);
#endif
#ifdef kMHQUEUE_LEN_ATTR
		call MHQueueLenAttr.registerAttr("mhqlen", UINT8, 1);
#endif
		call DepthAttr.registerAttr("depth", UINT8, 1);
		call QidAttr.registerAttr("qids", UINT16, 2);
		// call XmitCountAttr.registerAttr("xmitcnt", UINT8, 1);
		call QualityAttr.registerAttr("qual", UINT8, 1);
#ifdef kHAS_NEIGHBOR_ATTR
		call NeighborAttr.registerAttr("neigh", BYTES, 8);
#endif
		return SUCCESS;
	}

	command result_t StdControl.start()
	{
		return SUCCESS;
	}

	command result_t StdControl.stop()
	{
		return SUCCESS;
	}
		
#ifdef kHAS_NEIGHBOR_ATTR
	event result_t NeighborAttr.startAttr() {
	  return call ParentAttr.startAttrDone();
	}

	event result_t NeighborAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err) {
	  *err = SCHEMA_RESULT_READY;
	  call NetworkMonitor.getNeighbors(resultBuf);
	  return SUCCESS;
	}

	event result_t NeighborAttr.setAttr(char *name, char *resultBuf) {
	  return FAIL; //not supported
	}
#endif

	event result_t ParentAttr.startAttr()
	{
	  return call ParentAttr.startAttrDone();
	}

	event result_t ParentAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
	{
		*err = SCHEMA_RESULT_READY;
		*(uint16_t*)resultBuf = call NetworkMonitor.getParent();
		return SUCCESS;
	}
	event result_t ParentAttr.setAttr(char *name, char *resultBuf)
	{
		// don't allow manually setting parent
		return FAIL;
	}

#ifdef kCONTENT_ATTR
	event result_t ContentionAttr.startAttr()
	{
		return call ContentionAttr.startAttrDone();
	}

	event result_t ContentionAttr.getAttr(char *name, char* resultBuf, SchemaErrorNo *err) 
	{
		*err = SCHEMA_RESULT_READY;
		*(uint16_t*)resultBuf = call NetworkMonitor.getContention();
		return SUCCESS;
	}

	event result_t ContentionAttr.setAttr(char *name, char* resultBuf) 
	{
		return FAIL; //can't set
	}
#endif

	event result_t FreeSpaceAttr.startAttr()
	{
		return call FreeSpaceAttr.startAttrDone();
	}

  /** FreeSpaceAttr tracks the amount of RAM available in the local heap.
   */
  event result_t FreeSpaceAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
      *err = SCHEMA_RESULT_READY;
      *(uint16_t*)resultBuf = call MemAlloc.freeBytes();
      return SUCCESS;
    }

  event result_t FreeSpaceAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually setting of free space
      return FAIL;
    }
  event result_t MemAlloc.reallocComplete(Handle handle, result_t success)
  {
  	return SUCCESS;
  }
  event result_t MemAlloc.compactComplete()
  {
  	return SUCCESS;
  }
  event result_t MemAlloc.allocComplete(HandlePtr handle, result_t success)
  {
  	return SUCCESS;
  }

#ifdef kQUEUE_LEN_ATTR
	event result_t QueueLenAttr.startAttr()
	{
		return call QueueLenAttr.startAttrDone();
	}

  /** QueueLenAttr returns the send queue length for all messages
   */
  event result_t QueueLenAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
      *err = SCHEMA_RESULT_READY;
	  *(uint8_t*)resultBuf = call NetworkMonitor.getQueueLength();
      return SUCCESS;
    }

  event result_t QueueLenAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually this attribute
      return FAIL;
    }
#endif
#if 0
  /** XmitCountAttr returns the number of transmissions for the head
   * of send queue
   */
  event result_t XmitCountAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
      *err = SCHEMA_RESULT_READY;
	  *(uint8_t*)resultBuf = call NetworkMonitor.getXmitCount();
      return SUCCESS;
    }

  event result_t XmitCountAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually setting this attribute
      return FAIL;
    }
#endif
	event result_t QualityAttr.startAttr()
	{
		return call QualityAttr.startAttrDone();
	}

  /** QualityAttr returns a goodness measure of current parent
   */
  event result_t QualityAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
      *err = SCHEMA_RESULT_READY;
	  *(uint8_t*)resultBuf = call NetworkMonitor.getQuality();
      return SUCCESS;
    }

  event result_t QualityAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually setting this attribute
      return FAIL;
    }

#ifdef kMHQUEUE_LEN_ATTR
	event result_t MHQueueLenAttr.startAttr()
	{
		return call MHQueueLenAttr.startAttrDone();
	}

  /** MHQueueLenAttr returns the send queue length in multihop routing
   */
  event result_t MHQueueLenAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
      *err = SCHEMA_RESULT_READY;
	  *(uint8_t*)resultBuf = call NetworkMonitor.getMHopQueueLength();
      return SUCCESS;
    }

  event result_t MHQueueLenAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually setting of free space
      return FAIL;
    }
#endif

	event result_t DepthAttr.startAttr()
	{
		return call DepthAttr.startAttrDone();
	}

  /** DepthAttr returns the depth of the current node in multihop routing tree
   */
  event result_t DepthAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
      *err = SCHEMA_RESULT_READY;
	  *(uint8_t*)resultBuf = call NetworkMonitor.getDepth();
      return SUCCESS;
    }

  event result_t DepthAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually setting of free space
      return FAIL;
    }

	event result_t QidAttr.startAttr()
	{
		return call QidAttr.startAttrDone();
	}

  /** QidAttr returns the qids of the two currently running queries
   */
  event result_t QidAttr.getAttr(char *name, char *resultBuf, SchemaErrorNo *err)
    {
	  short numqs = call QueryProcessor.numQueries();
	  uint8_t qid1 = 0xff, qid2 = 0xff;
      *err = SCHEMA_RESULT_READY;
	  if (numqs >= 1)
	  	qid1 = (uint8_t)((call QueryProcessor.getQueryIdx(0))->qid);
	  if (numqs >= 2)
	  	qid2 = (uint8_t)((call QueryProcessor.getQueryIdx(1))->qid);
	  *(uint8_t*)resultBuf = qid1;
	  *(uint8_t*)(resultBuf + 1) = qid2;
      return SUCCESS;
    }

  event result_t QidAttr.setAttr(char *name, char *resultBuf)
    {
      // don't allow manually setting of free space
      return FAIL;
    }

  event result_t QueryProcessor.queryComplete(ParsedQueryPtr q)
  {
  	return SUCCESS;
  }
}
