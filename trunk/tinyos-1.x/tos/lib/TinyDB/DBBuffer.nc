// $Id: DBBuffer.nc,v 1.6 2003/10/07 21:46:20 idgay Exp $

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
includes DBBuffer;

/** The DBBuffer interface provides a place for queries to output their results
   to or fetch results from.
  <p>
   Buffers can be in RAM or simply drain out to the network.  In the case
   of RAM buffers, they have a fixed (preallocated) number of rows that
   are recycled according to some eviction policy.  Radio buffers have a
   single logical row that is written out via a RadioQueue interface.
   @author Sam Madden (madden@cs.berkeley.edu)
   
*/

interface DBBuffer {
  /** Enqueue a result into the specified buffer 
   @param bufferId The buffer to enqueue into
   @param r The result to enqueue
   @param pending (On return) Set to TRUE if the enqueue is still pending (completion singalled via  a putComplete event if TRUE)
   @param pq The query corresponding to this result
   @return err_OutOfMemory if the buffer is full
   @return err_ResultBufferBusy If other buffer requests are currently outstanding
     
  */
    command TinyDBError enqueue(uint8_t bufferId, QueryResultPtr r, bool *pending, ParsedQueryPtr pq);

    /*  1/23/03 DBBuffer.pop is no longer supported (SRM)
	Deallocate (without returning) the first item at the top of the queue.  
	To read the first item, use peek(), and call pop() when it is no longer needed
	@return err_NoMoreResults if no results are available
	
	command TinyDBError pop(uint8_t bufferId);
    */

    /** Copy the top most result in the specified buffer into buf

     if *pending is true on return, the result will not be available until getComplete 
     is signalled,  Otherwise, the result is available immediately. No
     further calls to dequeue/peek/getResult are allowed until putComplete is signalled.
     <p>
     Note that this routine may return a QueryResult that contains pointers into DBBuffer-local
     data structures which will be deallocated as soon as pop() is called.

     @return err_NoMoreResults if no results are available

    */
    command TinyDBError peek(uint8_t bufferId, QueryResult *buf, bool *pending);

    
  /* Copy the nth result in the specified buffer into buf
     <p>
     If *pending is TRUE on return, the result will not be available until getComplete 
     is signalled,  Otherwise, the result is available immediately. No
     further calls to dequeue/peek/getResult are allowed until putComplete is signalled.
     <p>
     Note that this routine may return a QueryResult that contains pointers into DBBuffer-local
     data structures which will be deallocated the fetched item is pop'ed() from the queue.
     
     @return err_ResultBufferBusy If other buffer requests are currently outstanding
     @return err_NoMoreResults  if idx > getSize() or if buffer[idx] is empty (unset)
    */
    command TinyDBError getResult(uint8_t bufferId, uint16_t idx, QueryResult *buf, bool *pending);


    /** Gets the index of field f in the specified buffer.
	@param bufferId The bufferId (returned from getBufferId) to look for field f in
	@param f The name of the desired field
	@param id (On return) The index of the specified field in bufferId, if the return code == err_NoError
	@return err_NoError on no error, err_UnsupportedBuffer or err_InvalidIndex on failure
    */
    command TinyDBError getFieldId(uint8_t bufferId, FieldPtr f, uint8_t *id);

    /** Gets the specified field from the QueryResult produced by reading from bufferId
	and writes the value into resultBuf.
	@param bufferId The bufferId (returned from getBufferId) that this is a query result for
	@param qr The query result (return from peek or getResult) to get the field from
	@param idx The index of the field to retrieve
	@param resultBuf The buffer to write the value of the field into
    */
    command TinyDBError getField(uint8_t bufferId, QueryResult *qr, uint8_t idx, char *resultBuf);

    /** Allocate the specified buffer with the specified size 
       sizes is an array of sizes of each field, with one entry per field

       Signals allocComplete when allocation is complete if *pending is true on return
       Data is buffer type specific data

       If *pending is true on return, the result will not be available until getComplete 
       is signalled,  Otherwise, the result is available immediately. No
       further calls to dequeue/peek/getResult are allowed until putComplete is signalled.

       @return err_UnsupportedPolicy if the specified policy can't be applied
       @return err_ResultBufferBusy If other buffer requests are currently outstanding
    */
    command TinyDBError alloc(uint8_t bufferId, BufferType type, uint16_t size, BufferPolicy policy,
			      ParsedQuery *schema, char *name, bool *pending, long data);

    /** @return the number of rows in the specified buffer */
    command uint16_t maxSize(uint8_t bufferId );
    
    /** @return the number of used rows in the buffer */
    command TinyDBError size(uint8_t bufferId, uint16_t *size);
    
    /** @return the schema of the results in the specified buffer */
    command ParsedQuery **getSchema(uint8_t bufferId );
    
    /** @param bufferId (on return) An unused buffer id
	@return the next unused buffer id (in bufferId), or err_OutOfMemory, if no mo buffers are available 
    */
    command TinyDBError nextUnusedBuffer(uint8_t *bufferId);
  
    /**	
	Looks up the buffer id that corresponds to the specified query id
	in bufferId <p>

	@param qid The query id to lookup
	@param bufferId (on return) The id of the buffer corresponding to qid
	@param isSpecial Is this a "special" (e.g. catalog buffer), or does it correspond to the results of an actual query
	@return err_InvalidIndex if no such buffer exists 	
    */
  command TinyDBError getBufferId(uint8_t qid, bool isSpecial, uint8_t *bufferId);

  /** Looks up the buffer id that corresponds to the specified name
      @param name The name of the buffer
      @param bufferId (on return) The id of buffer name
      @return err_InvalidIndex if no such buffer exists
  */
  command TinyDBError getBufferIdFromName(char *name, uint8_t *bufferId);

  /** Given a buffer id, return the query id which describes its schema */
  command TinyDBError qidFromBufferId(uint8_t bufId, uint8_t *qid);

  command TinyDBError openBuffer(uint8_t bufIdx, bool *pending);
  
#ifdef kMATCHBOX
  command TinyDBError loadEEPROMBuffer(char *name);
  command TinyDBError loadEEPROMBufferIdx(int i);
  command TinyDBError writeEEPROMBuffer(uint8_t bufId);
  command TinyDBError deleteEEPROMBuffer(uint8_t bufId);
  command TinyDBError cleanupEEPROM();

  event result_t deleteBufferDone(uint8_t bufId, TinyDBError err);
  event result_t writeBufferDone(uint8_t bufId, TinyDBError err);
  event result_t loadBufferDone(char *name, uint8_t idx, TinyDBError err);
  event result_t cleanupDone(result_t success);

#endif


  /** Signalled when a new result is enqueued in the specified buffer*/
  event result_t resultReady(uint8_t bufferId );

  /** Signalled when a result is dequeued from the specified buffer*/
  event result_t getNext(uint8_t bufferId );

  /** Signalled when allocation is complete for the specified buffer*/
  event result_t allocComplete(uint8_t bufferId, TinyDBError result);

  /** Signalled when a get is complete */
  event result_t getComplete(uint8_t bufferId, QueryResult *buf, TinyDBError result);

  /** Signalled when a put is complete */
  event result_t putComplete(uint8_t bufferId, QueryResult *buf, TinyDBError result);


  event result_t openComplete(uint8_t bufferId, TinyDBError result);
}
