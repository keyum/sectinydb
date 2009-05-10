// $Id: DBBufferC.nc,v 1.13 2003/10/07 21:46:20 idgay Exp $

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
#ifdef kMATCHBOX
includes Matchbox;
#endif

#ifndef NUMBUFFERS
#define NUMBUFFERS	4
#endif

module DBBufferC {
  uses {
    interface RadioQueue; //writes results out to a radio queue
    interface MemAlloc;
    interface QueryProcessor;
    interface Leds;
    interface CommandUse;
    interface QueryResultIntf;
    interface ParsedQueryIntf;
    interface TupleIntf;
    interface AttrUse;
#ifdef kMATCHBOX
    interface FileWrite;
    interface FileWrite as HeaderFileWrite;
    interface FileRead;
    interface FileRead as HeaderFileRead;
    interface FileRename;
    interface FileDelete;
    interface FileDir;
#endif
#ifdef kUART_DEBUGGER
    interface Debugger as UartDebugger;
#endif

    command void allocDebug();
  } 
  provides {
    interface DBBuffer;
    interface StdControl;
    interface CatalogTable;
#ifdef kMATCHBOX
    event result_t fsReady();
#endif
  }
}

#ifdef kUART_DEBUGGER
#define DEBUG(s,l)  (TOS_LOCAL_ADDRESS==0?l:(call UartDebugger.writeLine((s),(l))))
#else
#define DEBUG(s,l)
#endif

/**
<p>
   DBBuffer is a output buffer abstraction for TinyDB.  
   Buffers can be one of several types:
<p>
   Radio:  Results are written directly out to the radio
   Command:  Each result causes a command to be invoked
   RAM:  Results are written to a RAM buffer
   EEPROM:  Results are written to EEPROM
   Catalog buffers (e.g. event, attribute, command, query) that are read-only 
    and contain system meta-data.
<p>
   RAM and EEPROM buffers use a cicrular buffer, with nextFree and
   nextFull slots if nextFull slot is after nextFree slot, then used
   slots are from nextFull to the end of the buffer plus.  Otherwise,
   used slots are from nextFull to nextFree.
<p>
   To the outside world, buffer appears to have a number of used
   slots, with the first slot (0) beginning at nextFull.
<p>
<code>	 		
       nextFull > nextFree       	       	   nextFull < nextFree
       +--------------------------+ top	           +--------------------------+ top
       |..........................|                |                          |	   
       |.....used slots...........|                |      free slots          |	   
       |..........................|                |                          |	   
       |..........................|                |                          |	   
       +--------------------------+ nextFree       +--------------------------+	nextFull
       |                          |                |..........................|		
       |                          |                |..........................|                        	
       |                          |                |..........................|		
       |      free slots          |                |.......used slots.........|		
       |                          |                |..........................|		
       |                          |                |..........................|		
       |                          |                |..........................|		
       +--------------------------+ nextFull       +--------------------------+ nextFree
       |..........................|                |                          |	       	
       |.....used slots...........|                |                          |
       |..........................|                |       free slots         |
       |..........................|                |                          |
       +--------------------------+                +--------------------------+
</code>
*/

implementation {
  enum {
    kNUM_BUFS = NUMBUFFERS,
    kATTR_BUF = kNUM_BUFS + 1,
    kCOMMAND_BUF = kATTR_BUF + 1,
    kEVENT_BUF = kCOMMAND_BUF + 1,
    kQUERY_BUF = kEVENT_BUF + 1
  };

  typedef enum {
    kIDLE,
    kALLOC_SCHEMA,
    kALLOC_BUFFER,
    kALLOC_ROW,
    kALLOC_NAME,
    kREAD_ROW,
    kEEPROM_WRITE,
    kEEPROM_ALLOC_ROW,
    kREADING_LENGTH,   //stages in reading of data from EEPROM
    kALLOC_FOR_READ,
    kREADING_DATA,
    kWRITE_BUFFER,
    kHEADER_READ,
    kWRITE_FILE_COUNT, 
    kREAD_FILE_COUNT,
    kREAD_OPEN,
    kREAD_LENGTHS,
    kSKIP_BYTES,
    kREAD_NAME,
    kREAD_FIELD_LEN,
    kALLOC_FIELD_DATA,
    kREAD_FIELD_DATA,
    kALLOC_QUERY,
    kREAD_QUERY,
    kREAD_BUFFER,
    kWRITING_LENGTHS,
    kWRITING_NAME,
    kWRITING_QUERY,
    kWRITING_BUFFER,
    kWRITE_FIELD_LEN,
    kWRITE_FIELD_DATA,
    kWRITE_NEXT_BUFFER,
    kNOT_READY,
    kOPEN_BUFFER,
    kRADIO_ENQUEUE,
    kCLEANUP
 } AllocState;


  typedef struct {
    BufferType type;
    BufferPolicy policy;
    ParsedQuery **qh; //schema of buffer (rest of query fields ignored)
    uint16_t numRows; //number of rows in buffer
    uint16_t nextFree; //next free row
    uint16_t nextFull; //next full row (top of queue)

    uint16_t len; //length, in bytes, of buffers
    uint16_t rowSize; //length, in bytes, of one row

    long data;

    char **name;

    union {
      char **bufdata; //data handle for RAM buffers
      struct {
	bool isOpen; //has the eeprom been successfully opened
	bool isWrite;
      } eeprom;
    } u;
  } Buffer;

  Buffer mBuffers[kNUM_BUFS];
  long mUsedBufs;
  uint8_t mCurBuffer;
  uint16_t mCurRow;
  uint8_t mLen;
  uint8_t mSearchFile;
  uint8_t mCurFile;
  uint8_t mLenBytes[3];
  
  Handle mCurRowHandle;
  Handle mEepromRow;
  QueryResultPtr mCurResult;
  ParsedQuery *mAllocSchema, *mCurQuery;
  uint8_t mCurResultIdx;
  AllocState mState;

  char *mNamePtr;

  //#if defined(PLATFORM_PC)
  //#ifdef kDEBUG
  //#endif
#ifdef kDEBUG
  ParsedQueryPtr mQueryPtr;
  QueryResult mQr;
  short mInt;
  char tupleBuf[50];
  char queryBuf[100];
  char aggResult[7];
#endif

  char mDbgBuf[10];

  //static schemas for catalog buffers
  enum {NUM_ATTR_FIELDS = 1};
  uint8_t ATTR_TYPES[NUM_ATTR_FIELDS];
  uint8_t ATTR_SIZES[NUM_ATTR_FIELDS];
  char ATTR_NAMES[NUM_ATTR_FIELDS][STRING_SIZE];


  TinyDBError calcNextFreeRow(Buffer *buf);
  TinyDBError getBuf(uint8_t bufId, Buffer **buf);
  void cleanupBuffer(int i, int lineno);
  void initCatalog();
			
  TinyDBError getSpecialBufferId(BufferType type, uint8_t *bufferId);
  TinyDBError continueRadioBufferEnqueue();

#ifdef kMATCHBOX
  uint8_t mNumFiles;
  bool mLocalRead;
  Handle mNameHand;
  Handle mQueryHandle;
  AllocState mHeaderFileState, mAppendState;
  char *mCurBufName;
  uint8_t mCurBufId;
  Buffer *mReplaceBuf, *mAppendBuf;
  uint8_t mReplaceBufId;
  uint8_t mCurWriteIdx;
  bool mFoundBuffer;
  uint8_t mNumSkipBytes;
  bool mNameSearch;
  char mReadBuf[10];
  bool mDelete;
  char mCurName[15];
  bool mHasName;
  bool mAllocing;
  bool mDidFieldLen;

  TinyDBError doLoad();
  void headerReadFailed(TinyDBError err);
  TinyDBError writeFileCount();
  void writeCountDone(TinyDBError err);
  TinyDBError readFileCount();
  void readCountDone(TinyDBError err);
  void readBuffer(char *bufName, uint8_t bufId, TinyDBError err);

  task void loadBufferTask();
  task void appendBufferTask();
  task void replaceBufferTask();
  task void readEEPROMRow();

#define kVERSION_CODE 0x01 //the version of the DBBuffer 

#endif

  /* ----------------------------------- StdControl Methods ------------------------------------- */

  command result_t StdControl.init() {
    mUsedBufs = 1; //clear free bitmap -- can't use first buffer -- it's for the radio!
#ifdef kMATCHBOX
    mState = kNOT_READY; //wait until the EEPROM file system is ready
    mNumFiles = 0;
    mAllocing = FALSE;
    mHeaderFileState = kIDLE;
#else
    mState = kIDLE;
#endif
#ifdef kDEBUG
    mInt = 0;
#endif
    initCatalog();
    mEepromRow = NULL;


    
    return SUCCESS;
  }

  command result_t StdControl.start() {
#ifdef kDEBUG
    BufInfo buf;
    bool pending;
    TinyDBError err;
    Expr e;

    mQueryPtr = (ParsedQueryPtr)queryBuf;

    dbg(DBG_USR2, "start"); fflush(stdout);

    mQueryPtr->qid = 0;
    mQueryPtr->numFields = 1;
    mQueryPtr->numExprs = 1;
    mQueryPtr->epochDuration = 1024;
    mQueryPtr->clocksPerSample = 1024/32;
    mQueryPtr->clockCount = mQueryPtr->clocksPerSample;
    mQueryPtr->currentEpoch = 0;
    mQueryPtr->fromQid = kNO_QUERY;
    mQueryPtr->bufferType = kRAM;
    mQueryPtr->queryToSchemaFieldMap[0] = 1; //some field in the schema?
    memset(aggResult, 0, 7);
    aggResult[4]=10;
    aggResult[5]=10;
    aggResult[6]=10;
    
    e.opType = kAGG;
    e.idx = 0;
    e.fieldOp = FOP_NOOP;
    e.fieldConst = 0;
    e.ex.agg.field = 0;
    e.ex.agg.groupingField = kNO_GROUPING_FIELD;
    e.ex.agg.groupFieldOp = FOP_NOOP;
    e.ex.agg.groupFieldConst = 0;
    e.ex.agg.op = MIN;

    call ParsedQueryIntf.setExpr(mQueryPtr, 0, e);
    err = call DBBuffer.nextUnusedBuffer(&mQueryPtr->bufferId);
    if (err != err_NoError)
      dbg(DBG_USR2, "err, nextUnusedBuf: %d", err);
    buf.ram.numRows = 2;
    buf.ram.policy = EvictOldestPolicy;
    
    mQueryPtr->buf = buf;

    err = call DBBuffer.alloc(mQueryPtr->bufferId, kRAM, buf.ram.numRows, buf.ram.policy,&mQueryPtr, &pending, 0);
    if (err != err_NoError)
      dbg(DBG_USR2, "err, DBBuffer.alloc: %d", err);
    
#endif
      return SUCCESS;
  }

  command result_t StdControl.stop() {
      return SUCCESS;
  }


  void initCatalog() {
    ATTR_TYPES[0] = STRING;
    ATTR_SIZES[0] = sizeOf(STRING);
    strcpy(ATTR_NAMES[0],"name");
  }

#ifdef kDEBUG
  void enqueueResult() {
    bool pending;
    TinyDBError err;


    mInt++;

    dbg(DBG_USR2, "enqueuing"); fflush(stdout);

    err = call QueryResultIntf.initQueryResult(&mQr);
    if (err != err_NoError)
      dbg(DBG_USR2, "err, initQueryResult: %d", err);

    err = call QueryResultIntf.addAggResult(&mQr, 0, aggResult, 7, mQueryPtr, 0);
    if (err != err_NoError)
      dbg(DBG_USR2, "err, addAggResult: %d", err);

    err = call DBBuffer.enqueue(mQueryPtr->bufferId, &mQr, &pending, mQueryPtr);
    if (err != err_NoError)
      dbg(DBG_USR2, "err, enqueue: %d", err);


  }


  void readResult() {
    QueryResult qr;
    ParsedQuery *pq;
    TinyDBError err;
    short result;

    bool pending;
    Tuple *t;

    err = call DBBuffer.peek(mQueryPtr->bufferId, &qr, &pending);
    if (err != err_NoError)
      dbg(DBG_USR2, "error,peek: %d", err);
    err = call QueryResultIntf.toTuplePtr(&qr, mQueryPtr, &t);
    if (err != err_NoError)
      dbg(DBG_USR2, "error,toTuplePtr: %d", err);
    pq = *(call DBBuffer.getSchema(mQueryPtr->bufferId));

    dbg(DBG_USR2,"num fields = %d\n", pq->numFields);
    err = call ParsedQueryIntf.getResultField(pq, &qr, 0, (char *)&result);
    if (err != err_NoError)
      dbg(DBG_USR2, "error, %d", err);
    else
      dbg(DBG_USR2,"tuple.val = %d\n",result); fflush(stdout);
  }

#endif


  /* ----------------------------------- DBBuffer Methods ------------------------------------- */

  /** Enqueue a result into the specified buffer 
     Note that if pending returns true, this routine may store a reference to r (so it had better not be on the stack!)
   */
  command TinyDBError DBBuffer.enqueue(uint8_t bufferId, QueryResultPtr r, bool *pending, ParsedQuery *pq) {
    Buffer *buf;
    uint16_t row;
    TinyDBError err = err_NoError;
    Handle *bufList;

    *pending = FALSE;

    switch (bufferId) {
    case kRADIO_BUFFER: {
      if (mState != kIDLE) return err_ResultBufferBusy;


      mCurResult = r;
      mCurQuery = pq;
      mCurResultIdx = 0;

      err = continueRadioBufferEnqueue(); //try to send the first result
      if (mState != kIDLE) *pending = TRUE;
      return err;
    }
    case kATTR_BUF:
    case kEVENT_BUF:
    case kCOMMAND_BUF:
    case kQUERY_BUF:
      return err_UnsupportedBuffer;
    default:
      err = getBuf(bufferId, &buf);
      if (err != err_NoError) return err;
      break;
    }

    switch (buf->type) {
    case kCOMMAND: 
      {
	//low byte of data should be command id!
	char *cmdStr = (char *)&buf->data;
	CommandDescPtr cmd = call CommandUse.getCommandById((uint8_t)(cmdStr[0]));


	if (cmd!=NULL) {
	  ParamVals params;
	  SchemaErrorNo schema_err;
	  char result[1];


	  switch (cmd->params.numParams) {
	  case 0:
	    params.numParams = 0;
	    break;
	  case 1:
	    //command buffer supports 1 integer (short) parameter
	    if (cmd->params.params[0] != INT16 &&
		cmd->params.params[0] != UINT16 &&
		cmd->params.params[0] != INT8 &&
		cmd->params.params[0] != UINT8)
	      return err_UnknownError;
	    params.numParams = 1;
	    params.paramDataPtr[0] = &cmdStr[1]; //2nd and 3rd bytes are command param
	    break;
	  default:
	    return err_InvalidIndex;
	    
	  }
	  call CommandUse.invoke(cmd->name, result, &schema_err, &params);
      }
    }
    break;
      
    case kEEPROM:
      if (mState != kIDLE) {
	return err_ResultBufferBusy;
      }

      if (!buf->u.eeprom.isOpen) {
	return err_BufferNotOpen;
      }

      //must do this to increment row numbers, etc.
      err = calcNextFreeRow(buf);
      if (err != err_NoError) {
	return err;
      }
      
      mState = kEEPROM_ALLOC_ROW;
      mCurResult = r;
      mCurBuffer = bufferId;
      *pending = TRUE;
     
      mCurRowHandle = mEepromRow;


      if (mEepromRow == NULL) {
	//+ 1 since we need an extra byte for the length
	if (call MemAlloc.allocate(&mEepromRow, call QueryResultIntf.resultSize(r, pq) + 1) != SUCCESS) {
	  *pending = FALSE;
	  mState = kIDLE;
	  cleanupBuffer(bufferId, __LINE__);
	  return err_EepromFailure;
	}
      } else {
	//+ 1 since we need an extra byte for the length
	if (call MemAlloc.reallocate(mEepromRow, call QueryResultIntf.resultSize(r, pq) + 1) != SUCCESS) {
	  *pending = FALSE;
	  mState = kIDLE;
	  cleanupBuffer(bufferId, __LINE__);
	  return err_EepromFailure;
	}
      }
      break;
    case kRAM:
      if (mState != kIDLE) {
	return err_ResultBufferBusy;
      }
      mState = kALLOC_ROW;


      row = buf->nextFree;
      err = calcNextFreeRow(buf);
      if (err != err_NoError) {
	mState = kIDLE;
	return err;
      }

      //need to allocate the buffer for this row
      mCurResult = r;
      mCurRow = row;
      mCurBuffer = bufferId;

      *pending = TRUE;

      bufList = (Handle *)(*buf->u.bufdata);

        if (bufList[row] != NULL) { 
	  //realloc'ing can be much more efficient than allocing all over again, 
	  //especially if the results are the same size (which should be the common case) 
	  mCurRowHandle = bufList[row];
	  if (call MemAlloc.reallocate(bufList[row], call QueryResultIntf.resultSize(r, pq)) != SUCCESS) { 
	    *pending = FALSE; 
	    mState = kIDLE; 
	    cleanupBuffer(bufferId, __LINE__);
	    return err_OutOfMemory; 
	  } 
        } else { 
	  if (call MemAlloc.allocate(&mCurRowHandle, call QueryResultIntf.resultSize(r, pq)) != SUCCESS) {
	    *pending = FALSE;
	    mState = kIDLE;
	    cleanupBuffer(bufferId, __LINE__);
	    return err_OutOfMemory;
	  }
	}

      break;
    default:
      return err_UnknownError;
    }

    return err_NoError;
  }

  /* Given a query results in mCurResult, a query in mCurQuery, and a current result
     index in mCurResultIdx, send the next result out (if there are more to be sent),
     or do nothing.

     The caller can determine if results are being sent by looking at the value of
     the mState flag on return -- if is "kIDLE", nothing is being done, otherwise, a
     result is being sent.
  */
  TinyDBError continueRadioBufferEnqueue() {
    ParsedQuery *pq = mCurQuery;
    QueryResult *r = mCurResult;
    int numResults = call QueryResultIntf.numRecords(r, pq);
    QueryResult newqr;
    TinyDBError err = err_NoError;
    bool pending = FALSE;
    ResultTuple rtup;
    
    mState = kRADIO_ENQUEUE;

    if (mCurResultIdx >= numResults) {
      mState = kIDLE;
      return err_NoError;
    }
    rtup = call QueryResultIntf.getResultTuple(r, mCurResultIdx++, pq);
    if (rtup.error != err_NoError) {
      mState = kIDLE;
      return rtup.error;
    }
      
    err = call QueryResultIntf.fromResultTuple(rtup, &newqr, pq);
    if (err != err_NoError) {
      mState = kIDLE;
      return err;
    }
    
    
    err = call RadioQueue.enqueue((QueryResultPtr)&newqr, &pending);
    if (err != err_NoError)
      mState = kIDLE;

    if (pending)
      return err;
    else {
      if (err != err_NoError) {
	return err;
      }
      else return continueRadioBufferEnqueue(); //try to send the next result, if there is one
    }	

  }

  /*
     Remove the first element from the db buffer & deallocate it (don't return it.)
     Use peek() to retrieve the first element without deallocating, then call pop()
     when finished  (because peek returns a pointer into the buffer.)
  */

  /*

    
    1/23/02 SRM

    DBBuffer.pop is no longer supported!
    command TinyDBError DBBuffer.pop(uint8_t bufferId) {
    Buffer *buf;
    Handle data;
    uint16_t row; 
    Handle *bufList;
    TinyDBError err = err_NoError;

    err = getBuf(bufferId, &buf);
    if (err != err_NoError)
      return err;
    if (buf->nextFull == buf->nextFree)
      return err_NoMoreResults;
    row = buf->nextFull;
    bufList = (Handle *)(*buf->u.bufdata);
    data = bufList[row];
    if (data != NULL) {
      call MemAlloc.free(data);
      bufList[row] = NULL;
    }
    buf->nextFull++;
    if (buf->nextFull >= buf->numRows) buf->nextFull = 0;    
    return err;
  }
  */
 
  /** Copy the top most result in the buffer into buf
     @return err_NoMoreResults if no results are available
     @return err_UnsupportedBuffer if the buffer doesn't support peek/pop
  */
  command TinyDBError DBBuffer.peek(uint8_t bufferId, QueryResult *qr, bool *pending) {
    Buffer *buf;
    TinyDBError err;
    uint16_t row;
    Handle *bufList;

    if (bufferId == kRADIO || bufferId == kATTR_BUF || bufferId == kCOMMAND_BUF ||
	bufferId == kEVENT_BUF || bufferId == kQUERY_BUF)
      return err_UnsupportedBuffer;
    if (mState != kIDLE) {
      return err_ResultBufferBusy;
    }
    mState = kREAD_ROW;
    
    *pending = FALSE;

    //DEBUG("peek", 4);

    err = getBuf(bufferId, &buf);
    if (err != err_NoError) {
      mState = kIDLE;
      goto done;
    }


    switch(buf->type) {
    case kRAM:
      row= buf->nextFull;
      if (row == buf->nextFree && buf->numRows != 1) { //special case single row...
	err =  err_NoMoreResults;
	mState = kIDLE;
	goto done;
      }

      bufList = (Handle *)(*buf->u.bufdata);
      if (bufList[row] == NULL) {
	err =  err_NoMoreResults; 
	mState = kIDLE;
	goto done;
      }
      call QueryResultIntf.fromBytes((QueryResultPtr)*bufList[row], qr, *buf->qh);
      //memcpy(qr, &(*buf->u.bufdata)[row*buf->rowSize],buf->rowSize);
      mState = kIDLE;
      break;
    case kEEPROM:
#ifdef kMATCHBOX
      mCurBuffer = bufferId;
      mCurResult = qr;
      *pending = TRUE;
      if (!buf->u.eeprom.isOpen) {

	if (call FileRead.open(*buf->name) == FAIL) {
	  err = err_EepromFailure;
	  *pending = FALSE;
	  mState = kIDLE;
	}
      } else {
	if (buf->u.eeprom.isWrite) { //we can't read if it's open for writing
	  *pending = FALSE;
	  mState = kIDLE;
	  err = err_BufferOpenForWriting;
        } else {
	  post readEEPROMRow();
	}
      }
#else
      err = err_EepromFailure;
      *pending = FALSE;
      mState = kIDLE;
#endif

      break;

    default:
      err = err_UnknownError;
      mState = kIDLE;
    }

  done:
    //mState = kIDLE;
    return err;
  }

#ifdef kMATCHBOX
  /** Task to read a row from the EEPROM into mCurResult, 
     assuming mCurBuffer contains the ID of the buffer to
     be read from and ReadFile is currently open to the file
     associated with the buffer.
  */
  task void readEEPROMRow() {
    Buffer *buf;
    TinyDBError err;
    err = getBuf(mCurBuffer, &buf);
    if (err != err_NoError) {
      mState = kIDLE;
      signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_UnsupportedBuffer);
    }


    switch (mState) {
    case kREAD_ROW:
      mState = kREADING_LENGTH;
      buf->u.eeprom.isWrite = FALSE;
      buf->u.eeprom.isOpen = TRUE;
      if (call FileRead.read(&mLen, 1) == FAIL) {
	mState = kIDLE;
	signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_EepromFailure);
      }
      break;
    case kREADING_LENGTH:
      mState = kALLOC_FOR_READ;
      mCurRowHandle = mEepromRow;
      if (mEepromRow == NULL) {
	if (call MemAlloc.allocate(&mEepromRow, mLen) != SUCCESS) {
	  mState = kIDLE;
	  signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_OutOfMemory);
	}
      } else {
	if (call MemAlloc.reallocate(mEepromRow, mLen) != SUCCESS) {
	  mState = kIDLE;
	  signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_OutOfMemory);
	}
      }
      break;
    case kALLOC_FOR_READ:
      mState = kREADING_DATA;
      call MemAlloc.lock(mEepromRow);
      if (call FileRead.read(*mEepromRow, mLen) == FAIL) {
	mState = kIDLE;
	signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_EepromFailure);
      }
      break;
    case kREADING_DATA: 
      //HACK! -- this is fucked up -- query result now may have pointers into mEepromRow, which
      //will only be valid until the next call to read or write
      
      call QueryResultIntf.fromBytes((QueryResultPtr)*mEepromRow, mCurResult, *buf->qh);      

      //unlocking here is a BAD THING -- handle may move, result may become invalid
      // if it has pointers into mEeprom row, which will only be the case for
      // certain aggregate queries.

      call MemAlloc.unlock(mEepromRow);


      {
	TuplePtr t;
	char numStr[5];
	int i;

	call QueryResultIntf.toTuplePtr(mCurResult, *buf->qh, &t);
	itoa((*buf->qh)->numFields, numStr, 10);
	mDbgBuf[0] = 0;
	strcat(mDbgBuf, numStr);
	strcat(mDbgBuf, ",");
	for(i=0;i<(*buf->qh)->numFields;i++) {
	  itoa(*(uint16_t *)(call TupleIntf.getFieldPtr(*buf->qh, t, i)), numStr, 10);
	  if (strlen(mDbgBuf) + strlen(numStr) + 1< sizeof(mDbgBuf)) {
	    strcat(mDbgBuf, numStr);
	    strcat(mDbgBuf, ",");
	  }
	}
	DEBUG(mDbgBuf, strlen(mDbgBuf));

      }

      
      mState = kIDLE;
      signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_NoError);
      break;      
    default:
      return;
    }
  }
#endif

  /** Copy the nth result in the buffer into buf
     @return err_NoMoreResults  if idx > getSize() or if buffer[idx] is empty (unset)
  */
  command TinyDBError DBBuffer.getResult(uint8_t bufferId, uint16_t idx, QueryResult *qr, bool *pending) {
    TinyDBError err = err_NoError;

    if (mState != kIDLE) {
      return err_ResultBufferBusy;
    }
    mState = kREAD_ROW;

    switch (bufferId) {
      //is this a special case buffer
    case kATTR_BUF: {
      TuplePtr t;
      char *field;
      
      if (idx >= call AttrUse.numAttrs()) {
	err = err_NoMoreResults;
	goto done;
      }
      
      //the tuple part of the query result
      t = &qr->d.t;
      t->notNull = 0;
      t->numFields = NUM_ATTR_FIELDS;

      //HACK -- hard code the retrieval of catalog fields
      // FIELD 1 : Name

      field = call TupleIntf.getFieldPtrNoQuery(t, 0, NUM_ATTR_FIELDS, ATTR_SIZES, ATTR_TYPES);
      
      if (field != NULL) {
	AttrDescPtr adp = call AttrUse.getAttrById(idx);
	call TupleIntf.setFieldNoQuery(t,0,NUM_ATTR_FIELDS, ATTR_SIZES, ATTR_TYPES, adp->name);
      }
      break;
    }
    default:
      {
	Buffer *buf;
	uint16_t size;
	uint16_t row;
	Handle *bufList;

	err = getBuf(bufferId, &buf);	
	*pending = FALSE;
    
	if (err != err_NoError) goto done;
	
	if (buf->nextFull == buf->nextFree && buf->numRows != 1) {
	  err =  err_NoMoreResults;
	  goto done;
	}
	call DBBuffer.size(bufferId, &size);
	if (idx >= size) {
	  err = err_NoMoreResults;
	  goto done;
	}
    
	//see comment at beginning of document for info on slot management & indexing
	if (buf->nextFull > buf->nextFree) {
	  if (idx >= (buf->numRows - buf->nextFull)) {
	    row = idx - (buf->numRows - buf->nextFull);
	  } else
	    row = buf->nextFull + idx;
	} else {
	  row = buf->nextFull + idx;
	}
	
	switch (buf->type) {
	case kRAM:
	  bufList = (Handle *)(*buf->u.bufdata);
	  call QueryResultIntf.fromBytes((QueryResultPtr)*bufList[row], qr, *buf->qh);
	  //memcpy(qr, &(*buf->u.bufdata)[row*buf->rowSize], buf->rowSize);
	  break;
	default:
	  err =  err_UnknownError;
	}
      }
    }
  done:
    mState = kIDLE;
    return err;
  }

  /* Return the number of used rows in the buffer */
    command TinyDBError DBBuffer.size(uint8_t bufferId, uint16_t *size) {
      Buffer *buf;
      TinyDBError err = err_NoError;

      switch (bufferId) {
      case kATTR_BUF:
	*size = call AttrUse.numAttrs();
	return err_NoError;
      default:
	err = getBuf(bufferId, &buf);
	
	if (err != err_NoError) return err;
	
	//see comment at beginning of document for info on slot management & indexing
	if (buf->nextFull == buf->nextFree)
	  *size = 0;
	else if (buf->nextFull > buf->nextFree) {
	  *size = (buf->numRows - buf->nextFull) + buf->nextFree;
	} else {
	  *size = buf->nextFree - buf->nextFull;
	}
	break;
      }
      return err_NoError;
    }
  
    /** Allocate the buffer with the specified size 
	sizes is an array of sizes of each field, with one entry per field
	<p>
	Note that this may keep a reference to schema or name until after pending is complete (so 
	neither may be allocated on the callers stack!)
	<p>
	Signals allocComplete when allocation is complete if *pending is true on return
	@param bufferId The buffer to allocate
	@param type The type of the buffer (see DBBuffer.h -- only kRAM and kRADIO are supported)
	@param size The size (in rows) of the buffer
	@param policy The eviction policy to use with the buffer (see DBBuffer.h)
	@param schema The schema (layout) of rows in this buffer (expressed as a query)
	@param name The name of the schema (or NULL if it has no name)
	@param pending On return, set to true if the buffer is still being allocated (expect allocComplete if
	               true).
	@param data is currently unused
	@return err_UnsupportedPolicy if the specified policy can't be applied
    */
  command TinyDBError DBBuffer.alloc(uint8_t bufferId, BufferType type, uint16_t size, BufferPolicy policy,
				     ParsedQuery *schema, char *name, bool *pending, long data) {
    
    Buffer *buf;
    

    *pending = FALSE;
    
    if (mState != kIDLE) return err_ResultBufferBusy;

    if (bufferId >= kNUM_BUFS)
      return err_InvalidIndex;
    
    if (type == kRADIO)
      return err_UnsupportedBuffer; // can't do these right now

    if (mUsedBufs & (1 << bufferId))
      return err_ResultBufferInUse;
    
    mState = kALLOC_SCHEMA;

    buf = &mBuffers[bufferId];


    buf->type = type;
    buf->policy = policy;
    buf->numRows = size;
    buf->nextFree = 0;
    buf->nextFull = 0;
    buf->u.bufdata = NULL;
    buf->qh = NULL;
    buf->data = data;
    if (name == NULL) {
      buf->name = NULL;
    } 
    //we must allocate buffer name
    mNamePtr = name;

    switch (type) {
    case kEEPROM:
      if (mNamePtr == NULL) {
	mState = kIDLE;
	cleanupBuffer(bufferId, __LINE__);
	return err_NoUnnamedEepromBuffers;
      }
    case kRAM:
      buf->rowSize = sizeof(Handle); //rows are handles into memory
      buf->len = buf->rowSize * buf->numRows;

      mCurBuffer = bufferId;
      mAllocSchema = schema;
      
      //now, we have to allocate buf->u.bufdata and buf->q

      if (call MemAlloc.allocate((HandlePtr)(&buf->qh), call ParsedQueryIntf.pqSize(schema)) == SUCCESS) {
	*pending = TRUE;
	return err_NoError;
      } else {
	mState = kIDLE;
	cleanupBuffer(bufferId, __LINE__);
	return err_OutOfMemory;
      }
      break;

      
    case kCOMMAND:
      mState = kIDLE;
      mUsedBufs |= (1 << bufferId); 
      return err_NoError;
      break;
    default: 
      break;
    }


    return err_NoError;


  }
    
  /** @return the number of rows in this buffer */
  command uint16_t DBBuffer.maxSize(uint8_t bufferId) {
    Buffer *buf;
    TinyDBError err = getBuf(bufferId, &buf);
    if (err != err_NoError) return 0;
    
    return buf->numRows;
  }
  
  /** @return the schema of the result */
  command ParsedQuery **DBBuffer.getSchema(uint8_t bufferId) {
    Buffer *buf;
    TinyDBError err = getBuf(bufferId, &buf);
    if (err != err_NoError) return NULL;
    return buf->qh;
  }

  /** Copy the index of the named field f in bufferId (which was generated via a call to getBufferId)
      into id, if f exists in the result buffer
  */
  command TinyDBError DBBuffer.getFieldId(uint8_t bufferId, FieldPtr f, uint8_t *id) {
    TinyDBError err = err_NoError;
    ParsedQuery **fromPq;
    int i;
    switch (bufferId) {
    case kATTR_BUF:
      *id = NULL_QUERY_FIELD;
      for (i = 0; i < NUM_ATTR_FIELDS; i++) {
	if (strcmp(f->name,ATTR_NAMES[i]) == 0)
	  *id = i;
      }
      break;
    default:
      fromPq = call DBBuffer.getSchema(bufferId);
      if (fromPq == NULL) return err_UnsupportedBuffer;
      err = call ParsedQueryIntf.getResultId(*fromPq, f, id);
      if (err != err_NoError) {
	*id = NULL_QUERY_FIELD;
      }
      return err;
    }
    return err_NoError;
  }

  /** Copy data from the idxth field of qr into resultBuf.  qr must have been produced via a call to
      peek() or getResult() on the same bufferId.
  */
  command TinyDBError DBBuffer.getField(uint8_t bufferId, QueryResult *qr, uint8_t idx, char *resultBuf) {
    ParsedQuery **fromPq;
    Tuple *t;
    char *field;
    TinyDBError err = err_NoError;
    switch (bufferId) {
    case kATTR_BUF:
      if (idx >= NUM_ATTR_FIELDS) return err_InvalidIndex;
      t = &qr->d.t;
      field = call TupleIntf.getFieldPtrNoQuery(t, idx, NUM_ATTR_FIELDS, ATTR_SIZES, ATTR_TYPES);
      if (field != NULL) {
	  memcpy(resultBuf, field, ATTR_SIZES[idx]);
      } else
	err = err_InvalidIndex;
      break;
    default:
      fromPq = call DBBuffer.getSchema(bufferId);  
      if (fromPq == NULL) return err_UnsupportedBuffer;
      err = call ParsedQueryIntf.getResultField(*fromPq, 
						qr,
						idx,
						resultBuf);
    }
    return err;
  }

  /* Return the next unused buffer id, or err_OutOfMemory, 
     if no more buffers are available */
  command TinyDBError DBBuffer.nextUnusedBuffer(uint8_t *bufferId) {
    int i;

    for (i = 0; i < kNUM_BUFS; i++) {
      if (!(mUsedBufs & (1<<i))) { 
	*bufferId = i;
	return err_NoError;
      }
    }
    
    return err_OutOfMemory;

  }
  

  /** Looks up the buffer id that corresponds to the specified name
      @param name The name of the buffer
      @param bufferId (on return) The id of buffer name
      @return err_InvalidIndex if no such buffer exists
  */
  command TinyDBError DBBuffer.getBufferIdFromName(char *name, uint8_t *bufferId) {
    int i;
    
    //don't look at the the radio buffer!
    for (i = 1; i < kNUM_BUFS; i++) {
      if ((mUsedBufs & (1<<i))) {
	char *testName = *(mBuffers[i].name);
	if (strcmp(testName, name) == 0) {
	  //call UartDebugger.writeLine("got buf", 7);
	  *bufferId = i;
	  return err_NoError;
	}
      }
    }



    return err_InvalidIndex;

  }

  /** Given a buffer id, return the query id which describes its schema */
  command TinyDBError DBBuffer.qidFromBufferId(uint8_t bufId, uint8_t *qid) {
    if (bufId < kNUM_BUFS && (mUsedBufs & (1<<bufId))) {
      *qid = (**(mBuffers[bufId].qh)).qid;
      return err_NoError;
    } else {
      return err_InvalidIndex;
    }
  }


  /** @return the buffer id that corresponds to the specified bufIdx
      if special is false, bufIdx is just the query id that we want to read from
      otherwise, it's the index into special buffers -- e.g. catalog buffers -- that we want to use
  */
  command TinyDBError DBBuffer.getBufferId(uint8_t bufIdx, bool special, uint8_t *bufferId) {
    int i;
    int qid;

    if (special)
      return getSpecialBufferId(bufIdx, bufferId);

    qid = bufIdx;					 
    //don't look at the the radio buffer!
    for (i = 1; i < kNUM_BUFS; i++) {
      if ((mUsedBufs & (1<<i))) {
	if ((**mBuffers[i].qh).qid == qid) {
	  *bufferId = i;
	  return err_NoError;
	}
      }
    }

    return err_InvalidIndex;
  }

  /** Return the size of the requested field in a "special" catalog table.
      Return 0 if the field number is out of range or bufIdx is an
      unknown field.
  */
  command uint8_t CatalogTable.catalogFieldSize(uint8_t bufIdx, uint8_t fieldNo) {
    uint8_t bufferId;
    uint8_t numFields;
    uint8_t *sizes = NULL;

    if (getSpecialBufferId(bufIdx, &bufferId) != err_NoError)
      return 0;
    switch(bufferId) {
    case kATTR_BUF:
      numFields = NUM_ATTR_FIELDS; sizes = (char *)ATTR_SIZES;
      break;

    case kCOMMAND_BUF:
      //fill me in...
      break;

    case kEVENT_BUF:
      //fill me in...
      break;
      
    case kQUERY_BUF:      
      //fill me in...
      break;
    default:
      return 0;
    }
    if (fieldNo < NUM_ATTR_FIELDS && sizes != NULL)
      return sizes[fieldNo];
    else
      return 0;
      
  }

#ifdef kMATCHBOX

  /* ----------------- EEPROM Catalog Management Routines ----------------------- */

  // Erase all files in the EEPROM (be careful!)
  command TinyDBError DBBuffer.cleanupEEPROM() {
    if (mState == kIDLE) {
      mState = kCLEANUP;
      if (call FileDir.start() == FAIL)
	return err_EepromFailure;
      mHasName = FALSE;
      if (call FileDir.readNext() == FAIL)
	return err_EepromFailure;
    }
    else
      return err_ResultBufferBusy;

    return err_NoError;
  }

  event result_t FileDir.nextFile(const char *name, fileresult_t result) {
    if (result == FS_OK) {
      if (!mHasName) { //get a name
	strcpy(mCurName, name);
	DEBUG(mCurName, strlen(mCurName));
	mHasName = TRUE;
      }
      if (call FileDir.readNext() != FAIL) //then skip to the end of the iterator
	return SUCCESS;
    } //fall through on failure
    
    if (mHasName) {  //if we found a name, there's something to delete

      if (call FileDelete.delete(mCurName) == FAIL) {
	mState = kIDLE;
	signal DBBuffer.cleanupDone(FAIL);
      }
    } else {  //otherwise, we're all done
      mState = kIDLE;
      mNumFiles = 0;
      DEBUG("clean", 5);
      signal DBBuffer.cleanupDone(SUCCESS);
    }

    return SUCCESS;

  }
#endif

  /** Open the specified buffer for writing */
  command TinyDBError DBBuffer.openBuffer(uint8_t bufIdx, bool *pending) {
    Buffer *buf;


    if ( bufIdx >= kNUM_BUFS || !(mUsedBufs & (1<<bufIdx))) {      
      return err_IndexOutOfBounds;
    }
    if (mState == kIDLE) {
      mState = kOPEN_BUFFER;
      mCurBuffer = bufIdx;
    } else return err_ResultBufferBusy;


    buf = &mBuffers[bufIdx];
    if (buf->type == kEEPROM) {
#ifdef kMATCHBOX
      *pending = TRUE;
      if (call FileWrite.open(*(buf->name), FS_FCREATE | FS_FTRUNCATE) == FAIL) {
	return err_EepromFailure;
	mState = kIDLE;
      } else
	return err_NoError;
#else
      mState = kIDLE;
      *pending = FALSE;
      return err_NoMatchbox;
#endif

    } else {
      *pending = FALSE;
      mState = kIDLE;
      return err_NoError;
    }
  }


#ifdef kMATCHBOX
  /** Read information about a particular buffer in from the EEPROM */
  command TinyDBError DBBuffer.loadEEPROMBuffer(char *name) {
      mCurBufName = name;
      mNameSearch = TRUE;
      return doLoad();
  }

  command TinyDBError DBBuffer.loadEEPROMBufferIdx(int i) {
    mNameSearch = FALSE;
    mSearchFile = i;
    if (i < 0 || i >= mNumFiles)
      return err_IndexOutOfBounds;
    return doLoad();
  }


  //shared routine for handling reading info about a specific buffer
  TinyDBError doLoad() {
    // we can get here from headerFileWrite, which is OK
    //  must be careful, however, to leave mState == kWRITE_BUFFER on exit
    if (mHeaderFileState == kIDLE && (mState == kIDLE || mState == kWRITE_BUFFER)) {
      result_t err;

      mHeaderFileState = kREAD_OPEN;
      if (mState == kIDLE) mState = kHEADER_READ;

      mCurFile = 0; //index so far
      if (call DBBuffer.nextUnusedBuffer(&mCurBufId) != err_NoError) {
	if (mState == kHEADER_READ) mState = kIDLE;
	return err_OutOfMemory;
      }
      
      //allocate this thing
      mUsedBufs |= (1 << mCurBufId);

      err = call HeaderFileRead.open("tdbBufs");
      if (err != SUCCESS) {
	//DEBUG("fail",4);
	mHeaderFileState = kIDLE;
	if (mState == kHEADER_READ) mState = kIDLE;
	return err_EepromFailure;
      }
      return err_NoError;
    }  else
      return err_ResultBufferBusy;
  }


  /* Task to read info about the buffer named mCurBufName into buffer mCurBufId
     Scans the buffers in the eeprom file HeaderFileRead, looking for buffers of the
     appropriate name.
     
     signals loadBufferDone, with err_NoError on success, or some other error code
     on failure (including buffer not found).

     This is pretty ugly;  we have to (through a long series of split phase steps)

     - read length of name and query handle
     - allocate name
     - read name
     - compare name to mCurBufName
     - if not equal, skip remaining data and repeat
     - if equal, 
     - allocate query handle
     - read query handle
     - read buffer data
     - set handle and name in buffer data

  */
  #define min(x,y) ((x) < (y) ? (x) : (y))

  task void loadBufferTask() {
    int numBytes;
    TinyDBError err = err_NoError;
    switch (mHeaderFileState) {
    case kREAD_OPEN:
      //now, we need to read the length of the name and the parsed query, which follow
      mHeaderFileState = kREAD_LENGTHS;
      if (call HeaderFileRead.read(mLenBytes, 3) != SUCCESS) {
	//DEBUG("fail_len", 8);
	err = err_EepromFailure;
	goto fail;
      }
      break;
    case kREAD_LENGTHS:
      //DEBUG("READLENGTH",10);
      //now allocate storage for the name
      mHeaderFileState = kALLOC_NAME;
      //could check version code here?

      if (call MemAlloc.allocate(&mNameHand, mLenBytes[1] + 1) == FAIL) {
	err = err_OutOfMemory;
	goto fail;
      }
      break;
    case kALLOC_NAME:
      //DEBUG("ALLOCNAME",9);
      //read in the name
      ((char *)(*mNameHand))[mLenBytes[1]] = 0;
      mHeaderFileState = kREAD_NAME;
      call MemAlloc.lock(mNameHand);
      if (call HeaderFileRead.read(*mNameHand, mLenBytes[1]) != SUCCESS) {
	err = err_EepromFailure;
	goto fail;
      }
      break;
    case kREAD_NAME:
      //now compare read name to actual name
      call MemAlloc.unlock(mNameHand);

       DEBUG((char *)*mNameHand, strlen((char *)*mNameHand));
      if ((mNameSearch && strcmp(*mNameHand, mCurBufName) != 0) ||
	  (!mNameSearch && mCurFile != mSearchFile)) {
	mHeaderFileState = kSKIP_BYTES;  //move on to the next file
	mDidFieldLen = FALSE;
	mNumSkipBytes = mLenBytes[2] + sizeof(Buffer); //skip the query data plus the buffer data
	call MemAlloc.free(mNameHand);
	mNameHand = NULL; 
	post loadBufferTask();
      } else {
	mHeaderFileState = kALLOC_QUERY;
	if (call MemAlloc.allocate(&mQueryHandle, mLenBytes[2]) == FAIL) {
	  err = err_OutOfMemory;
	  goto fail;
	}

      }
      break;
    case kSKIP_BYTES:
      if (mNumSkipBytes == 0) {
	if (!mDidFieldLen) {
	  mDidFieldLen = TRUE;
	  //read in the number of field info bytes to skip
	  if (call HeaderFileRead.read(&mNumSkipBytes,1) != SUCCESS) { 
	    err = err_EepromFailure;
	    goto fail;
	  }
	} else {
	  if (++mCurFile < mNumFiles) {
	    mHeaderFileState = kREAD_OPEN; //check the next file
	    post loadBufferTask();
	  }
	  else {
	    err = err_IndexOutOfBounds;
	    goto fail;
	  }
	}
      } else {
	numBytes = min(sizeof(mReadBuf), mNumSkipBytes);
	mNumSkipBytes -= numBytes;
	if (call HeaderFileRead.read(mReadBuf, numBytes) != SUCCESS) {
	  err = err_EepromFailure;
	  goto fail;
	}
      }
      break;
    case kALLOC_QUERY:
      mHeaderFileState = kREAD_QUERY;
      call MemAlloc.lock(mQueryHandle);
      if (call HeaderFileRead.read(*mQueryHandle, mLenBytes[2]) != SUCCESS) {
	err = err_EepromFailure;
	goto fail;
      }
      break;
    case kREAD_QUERY:
      //finally, read the buffer data in
      call MemAlloc.unlock(mQueryHandle);

      mHeaderFileState = kREAD_BUFFER;
      if (call HeaderFileRead.read(&mBuffers[mCurBufId], sizeof(Buffer)) != SUCCESS) {
	err = err_EepromFailure;
	goto fail;
      }
      break;
    case kREAD_BUFFER:
      //DEBUG("READBUFFER", 10);

      mBuffers[mCurBufId].name = (char **)mNameHand;
      mNameHand = NULL;
      mBuffers[mCurBufId].qh = (ParsedQuery **)mQueryHandle;
      mBuffers[mCurBufId].u.eeprom.isOpen = FALSE;
      mBuffers[mCurBufId].u.eeprom.isWrite = FALSE;
      mQueryHandle = NULL;
      
      //now, we have to read in the length of the extra field data (names and types for buffers)
      mHeaderFileState = kREAD_FIELD_LEN;


      if (call HeaderFileRead.read(mLenBytes, 1) != SUCCESS) {
	err = err_EepromFailure;
	goto fail;
      }
      break;


    case kREAD_FIELD_LEN: //now, alloc the field data, if needed
      if (mLenBytes[0] == 0) {
	mHeaderFileState = kREAD_FIELD_DATA;
	post loadBufferTask();
      } else {
	mHeaderFileState = kALLOC_FIELD_DATA;
	if (call MemAlloc.allocate(&mNameHand, mLenBytes[0]) == FAIL) {
	  err = err_OutOfMemory;
	  goto fail;
	}
      }

      break;
    case kALLOC_FIELD_DATA:
      mHeaderFileState = kREAD_FIELD_DATA;
      call MemAlloc.lock(mNameHand);
      if (call HeaderFileRead.read(*mNameHand, mLenBytes[0]) == FAIL) {
	err = err_EepromFailure;
	goto fail;
      }
      break;
      
    case kREAD_FIELD_DATA:
      //finally, we're done -- set up the buffer and return
      if (mNameHand != NULL)
	call MemAlloc.unlock(mNameHand);
      (**mBuffers[mCurBufId].qh).tableInfo = (QueryTableHand)mNameHand; //it's ok if mNameHand is null
      mNameHand = NULL;

      mHeaderFileState = kIDLE;
      if (mState == kHEADER_READ) mState = kIDLE;
      call HeaderFileRead.close();
      if (mLocalRead) 
	readBuffer(mCurBufName, mCurBufId, err_NoError);
      else {

	DEBUG("load",4);
	signal DBBuffer.loadBufferDone(mCurBufName, mCurBufId, err_NoError);
      }
      break;
    default:
      break;
    }

    return;
      
    fail:
      headerReadFailed(err);
  }

  void headerReadFailed(TinyDBError err) {
    result_t r;

      if (mQueryHandle != NULL) {
	call MemAlloc.unlock(mQueryHandle);
	call MemAlloc.free(mQueryHandle);
	mQueryHandle = NULL;
      }
      if (mNameHand != NULL) {
	call MemAlloc.unlock(mNameHand);
	call MemAlloc.free(mNameHand);
	mNameHand = NULL;
      }
      mHeaderFileState = kIDLE;
      if (mState == kHEADER_READ) mState = kIDLE;

      mUsedBufs &= (0xFFFFFFFF ^ (1 << mCurBufId)); //mark this buffer as unused 
      r = call HeaderFileRead.close();
	
      if (mLocalRead) 
	readBuffer(mCurBufName, 0, err);
      else
	signal DBBuffer.loadBufferDone(mCurBufName, 0, err);


  }

  /** Flush this buffer to disk.

      The basic idea is to rewrite the entire list of buffers,
      replacing the buffer currently named buf.name with the
      data in buf.
      
      If no buffer named buf exists, just append the new buffer
      onto the end of the old data.

      This is pretty complicated;  for each buffer, we have to:
      
      - read it in (with loadEEPROMBuffer, which will call readBuffer when it's done)
      - check and see if it is named buf.name  (with replaceBufferTask)
      -  if so, overwrite it with buf (with appendBufferTask)
      -  otherwise rewrite it (with appendBufferTask)
      - if buf hasn't been written the end of all buffers, (with appendBufferTask)
        append it to the end

      Note the the performance of this routine really sucks, since we do a
      scan of the buffer info file to get information about each buffer, and then
      write it out.

   */
  TinyDBError doWrite(uint8_t buf);

  command TinyDBError DBBuffer.writeEEPROMBuffer(uint8_t bufId) {
    if (mState == kIDLE) {
      mDelete = FALSE;
      return doWrite(bufId);
    } else return err_ResultBufferBusy;
  }

  command TinyDBError DBBuffer.deleteEEPROMBuffer(uint8_t bufId) {
    if (mState == kIDLE) {
      mDelete = TRUE;
      return doWrite(bufId);
    } else return err_ResultBufferBusy;
  }

  TinyDBError doWrite(uint8_t buf) {
    fileresult_t err;

    //read all of the buffers, write them 
    mState = kWRITE_BUFFER;
    
    if (buf >= kNUM_BUFS || (mUsedBufs & (1 << buf)  == 0))
	return err_IndexOutOfBounds;

    //    DEBUG("writeBuf", 8);
    
    mReplaceBuf = &mBuffers[buf];
    mReplaceBufId = buf;
    mCurWriteIdx = 0;
    mLocalRead = TRUE;
    mFoundBuffer = FALSE;
    if ((err = call HeaderFileWrite.open("tdbBufs2", FS_FCREATE | FS_FTRUNCATE)) != SUCCESS) {
      mState = kIDLE;
      return err_EepromFailure;
    } else return err_NoError;
  }


  //Write the count of the number of buffers to the "numBuffers" file"
  TinyDBError writeFileCount() {
    if (mState == kIDLE) {
      mState = kWRITE_FILE_COUNT;
      if (call HeaderFileWrite.open("numBuffers", FS_FCREATE | FS_FTRUNCATE) != SUCCESS)  {
	mState = kIDLE;
	return err_EepromFailure;
      }
    }
    else 
      return err_ResultBufferBusy;    
  }

  void writeCountDone(TinyDBError err) {
    //DEBUG("wrote ok", 8);
    if (mDelete) 
	signal DBBuffer.deleteBufferDone(mReplaceBufId, err);
    else {
      if (mAllocing) {
	if (mReplaceBufId == mCurBuffer) {
	  signal DBBuffer.allocComplete(mCurBuffer, err);
	}
      } else {
	signal DBBuffer.writeBufferDone(mReplaceBufId, err);
      }
    }
  }

  //Read the count of the number of buffers from the "numBuffers" file
  TinyDBError readFileCount() {
    if (mState == kIDLE) {
      mState = kREAD_FILE_COUNT;
      if (call HeaderFileRead.open("numBuffers") != SUCCESS) {
	mState = kIDLE;
	return err_EepromFailure;
      }

    } else
      return err_ResultBufferBusy; 
    return err_NoError;
 }

  void readCountDone(TinyDBError err) {
  }

  task void appendBufferTask() {    
    mLocalRead = TRUE;
    switch (mAppendState) {
    case kWRITING_LENGTHS: //first, write the header
      mAppendState = kWRITING_NAME;
      mLenBytes[0] = kVERSION_CODE;
      mLenBytes[1] = strlen(*(mAppendBuf->name));
      mLenBytes[2] = call ParsedQueryIntf.pqSize(*mAppendBuf->qh);
      //DEBUG("LENGTHS",6);
      if (call HeaderFileWrite.append(mLenBytes, 3) != SUCCESS) {
	mAppendState = mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      }
      break;
    case kWRITING_NAME:  //then write the name
      call MemAlloc.lock((Handle)mAppendBuf->name);
      //DEBUG("NAME",4);
      mAppendState = kWRITING_QUERY;
      if (call HeaderFileWrite.append(*(mAppendBuf->name), strlen(*(mAppendBuf->name))) != SUCCESS) {
	call MemAlloc.unlock((Handle)mAppendBuf->name);
	mAppendState = mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      }
      break;
    case kWRITING_QUERY:  //then write the query
      call MemAlloc.unlock((Handle)mAppendBuf->name);
      call MemAlloc.lock((Handle)mAppendBuf->qh);
      mAppendState = kWRITING_BUFFER;
/*        { */
/*  	char map[5]; */
/*  	int i; */
/*  	ParsedQuery *q = *(mAppendBuf->qh); */

/*  	mDbgBuf[0] =0; */
/*  	strcat(mDbgBuf, "w:"); */
/*  	for (i = 0; i < q->numFields ; i++) { */
/*  	  itoa(q->queryToSchemaFieldMap[i], map, 10);	  */
/*  	  strcat(mDbgBuf, map);  */
/*  	  strcat(mDbgBuf, ",");  */
/*  	} */

/*  	DEBUG(mDbgBuf, strlen(mDbgBuf)); */
/*        } */
      if (call HeaderFileWrite.append(*(mAppendBuf->qh), call ParsedQueryIntf.pqSize(*mAppendBuf->qh)) != SUCCESS) {
	call MemAlloc.unlock((Handle)mAppendBuf->qh);
	mAppendState = mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      }
      break;

    case kWRITING_BUFFER:  //write the buffer data
      call MemAlloc.unlock((Handle)mAppendBuf->qh);
      mAppendState = kWRITE_FIELD_LEN;
      //      DEBUG("BUFFER", 6);
      if (call HeaderFileWrite.append(mAppendBuf, sizeof(Buffer)) != SUCCESS) {
	mAppendState = mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      }
      break;

    case kWRITE_FIELD_LEN:  //now write the extra field data length
      if ((**mAppendBuf->qh).tableInfo == NULL) {
	mAppendState = kWRITE_NEXT_BUFFER;
	mLenBytes[0] = 0;  // no data -- length is 0
      } else {
	mAppendState = kWRITE_FIELD_DATA;
	mLenBytes[0] = (uint8_t)(call MemAlloc.size((Handle)(**mAppendBuf->qh).tableInfo));
      }
      //      DEBUG("FIELDLEN", 8);
      if (call HeaderFileWrite.append(mLenBytes, 1) != SUCCESS) {
	mAppendState = mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      }
      break;
    case kWRITE_FIELD_DATA:  
      //assume tableInfo is non-null
      //DEBUG("FIELDDATA", 9);
      call MemAlloc.lock((Handle)(**mAppendBuf->qh).tableInfo);
      mAppendState = kWRITE_NEXT_BUFFER;
      if (call HeaderFileWrite.append(*(**mAppendBuf->qh).tableInfo, mLenBytes[0]) != SUCCESS) {
	call MemAlloc.unlock((Handle)(**mAppendBuf->qh).tableInfo);
	mAppendState = mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);	
      }
      break;

    case kWRITE_NEXT_BUFFER:
      //DEBUG("NEXT", 4);
      if ((**mAppendBuf->qh).tableInfo != NULL)
	call MemAlloc.unlock((Handle)(**mAppendBuf->qh).tableInfo);
      if (mCurWriteIdx < mNumFiles && !mFoundBuffer) {
	call DBBuffer.loadEEPROMBufferIdx(mCurWriteIdx);
      } else if (!mFoundBuffer) {
	mFoundBuffer = TRUE;
	mAppendBuf = mReplaceBuf;
	mAppendState = kWRITING_LENGTHS;
	mNumFiles++;
	post appendBufferTask();
      } else
	call HeaderFileWrite.close();
      break;
    default:
      break;
    }
  }
  
  task void replaceBufferTask() {
    mAppendState = kWRITING_LENGTHS;
    if (strcmp(*mBuffers[mCurBufId].name, *mReplaceBuf->name) == 0) {
      mFoundBuffer = TRUE;
      if (mDelete) {
	mAppendState = kWRITE_NEXT_BUFFER; //skip over it
      } else {
	mAppendBuf = mReplaceBuf;
      }
    } else {
      mAppendBuf = &mBuffers[mCurBufId];
    }
    mCurWriteIdx++;

    post appendBufferTask();
  }


  void readBuffer(char *bufName, uint8_t bufId, TinyDBError err) {
    mLocalRead = FALSE;
    if (err == err_NoError) {
      post replaceBufferTask(); //do the next one
    } else {
      if (mDelete) 
	signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
      else
	signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
    }
  }

  // HeaderFileRead routines
  event result_t HeaderFileRead.readDone(void *buffer, filesize_t nRead, fileresult_t result) {
    switch (mState) {
    case kHEADER_READ:
    case kWRITE_BUFFER: //can read header file while writing buffer
      if (mHeaderFileState != kIDLE) {
	if (result != FS_OK) {
	  //DEBUG("bad open", 8);
	  headerReadFailed(err_EepromFailure);
	}
	else { 

	  post loadBufferTask();
	}
      }
      break;
    case kREAD_FILE_COUNT:
/*        { */
/*  	char readStr[5]; */
	
/*  	mDbgBuf[0] = 0;  */
/*  	strcat(mDbgBuf, "cnt:");  */
/*  	itoa(*(uint8_t *)buffer, readStr, 10);  */
/*  	strcat(mDbgBuf, readStr);  */
/*  	DEBUG(mDbgBuf, strlen(mDbgBuf));  */
/*        } */

      call HeaderFileRead.close();
      mState = kIDLE; //done reading
      if (result!= FS_OK) 
	readCountDone(err_EepromFailure);
      else {
	readCountDone(err_NoError);
	//call DBBuffer.cleanupEEPROM();
      }
      break;
    default:
      break;
    }
    return SUCCESS;
  }
  
  event result_t HeaderFileRead.remaining(filesize_t n, fileresult_t result) {
    return SUCCESS;
  }


  event result_t HeaderFileRead.opened(fileresult_t result) {
    
    switch (mState) {
    case kHEADER_READ:
    case kWRITE_BUFFER: //can read header file while writing buffer
      if (mHeaderFileState != kIDLE) {
	if (result != FS_OK) {
	  //DEBUG("open bad", 8);
	  headerReadFailed(err_EepromFailure);
	} else {
	  //DEBUG("got open", 8);
	  post loadBufferTask();
	}
      }
      break;
    case kREAD_FILE_COUNT:
      if (result != FS_OK) {
	mState = kIDLE;
	readCountDone(err_EepromFailure);
      } else {
	//	DEBUG("getCnt", 6);
	if (call HeaderFileRead.read(&mNumFiles, 1) != SUCCESS) {
	  mState = kIDLE;
	  call HeaderFileRead.close();
	  readCountDone(err_EepromFailure);
	}
      }
    default:
      break;

      
    }
    return SUCCESS;
  }


  //HeaderFileWrite routines
  event result_t HeaderFileWrite.opened(filesize_t sz, fileresult_t result) {
    switch (mState) {
    case kWRITE_BUFFER:
      if (result != FS_OK) {
	//DEBUG("failOpen", 8);
	mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      } else {
	if (mNumFiles == mCurWriteIdx) {
	  mAppendState = kWRITE_NEXT_BUFFER;
	  post appendBufferTask(); //move on out...
	} else {
	  //DEBUG("bufOpen", 7);
	  call DBBuffer.loadEEPROMBufferIdx(mCurWriteIdx);
	  
	}
      }
      break;
    case kWRITE_FILE_COUNT:
      if (result != FS_OK) {
	mState = kIDLE;
	writeCountDone(err_EepromFailure);
      } else {
/*  	{ */
/*  	  char readStr[5]; */
	  
/*  	  mDbgBuf[0] = 0;  */
/*  	  strcat(mDbgBuf, "wcnt:");  */
/*  	  itoa(mNumFiles, readStr, 10);  */
/*  	  strcat(mDbgBuf, readStr);  */
/*  	  DEBUG(mDbgBuf, strlen(mDbgBuf));  */
/*  	} */

	if (call HeaderFileWrite.append(&mNumFiles, 1) != SUCCESS) {
	  mState = kIDLE;
	  writeCountDone(err_EepromFailure);
	}
      }
      break;
    default:
      break;
    }
    return SUCCESS;

  }

  event result_t HeaderFileWrite.appended(void *buffer, filesize_t nWritten, fileresult_t result) {
    switch (mState) {
    case kWRITE_BUFFER:
      if (result != FS_OK) {
	//make sure we clean up
	call MemAlloc.unlock((Handle)mAppendBuf->name);
	call MemAlloc.unlock((Handle)mAppendBuf->qh);
	mState = kIDLE; //HACK: unset state so we don't renamed files, etc after close
	call HeaderFileWrite.close();
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      } else {
	post appendBufferTask();
      }
      break;
    case kWRITE_FILE_COUNT:
      //close, even if there was an error
      call HeaderFileWrite.close();

      break;
    default:
      break;
    }
    return SUCCESS;
  }


  event result_t HeaderFileWrite.closed(fileresult_t result) {
    switch (mState) {
    case kWRITE_BUFFER:
      if (result == FS_OK) {
	//remove the old "tdbBufs" file
	call FileDelete.delete("tdbBufs");
      } else {
	mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);

      }
      break;
    case kWRITE_FILE_COUNT:
      mState = kIDLE;
      writeCountDone(result == FS_OK ? err_NoError : err_EepromFailure);
      break;
    default:
      break;
    }
    return SUCCESS;
  }



  event result_t HeaderFileWrite.reserved(filesize_t reservedSize, fileresult_t result) {
    return SUCCESS;
  }

  event result_t HeaderFileWrite.synced(fileresult_t result) {
    return SUCCESS;
  }



  //FileDelete Routines
  event result_t FileDelete.deleted(fileresult_t result) {
    if (mState == kWRITE_BUFFER) {
      if (result == FS_OK || result == FS_ERROR_NOT_FOUND) {
	call FileRename.rename("tdbBufs2", "tdbBufs");
      } else {
	mState = kIDLE;
	if (mDelete) 
	  signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
	else
	  signal DBBuffer.writeBufferDone(mReplaceBufId,err_EepromFailure);
      }
    } else if (mState == kCLEANUP) {
      if (result == FS_OK) {
	mHasName = FALSE;
	call FileDir.start();
	call FileDir.readNext();
      } else {
	mState = kIDLE;
	signal DBBuffer.cleanupDone(FAIL);
      }
    }
    return SUCCESS;
  }


  //FileRename Routines
  event result_t FileRename.renamed(fileresult_t result) {
    if (result == FS_OK) {
      mState = kIDLE;
      writeFileCount();
    } else {
      mState = kIDLE;
      if (mDelete) 
	signal DBBuffer.deleteBufferDone(mReplaceBufId, err_EepromFailure);
      else
	signal DBBuffer.writeBufferDone(mReplaceBufId ,err_EepromFailure);
    }
    return SUCCESS;
  }

#endif
  

  /* --------------------- Default event handlers ------------------------- */
  default event result_t DBBuffer.resultReady(uint8_t bufferId) {
    return SUCCESS;
  }

  default event result_t DBBuffer.getNext(uint8_t bufferId) {
    return SUCCESS;
  }

  default event result_t DBBuffer.allocComplete(uint8_t bufferId, TinyDBError result) {

    return SUCCESS;
  }

  default event result_t DBBuffer.putComplete(uint8_t bufferId, QueryResult *buf, TinyDBError result) {

    return SUCCESS;
  }

#ifdef kMATCHBOX
  default event result_t DBBuffer.writeBufferDone(uint8_t bufId, TinyDBError err) {
    return SUCCESS;
  }

  default event result_t DBBuffer.cleanupDone(result_t success) {
    readCountDone(success == SUCCESS ? err_NoError : err_EepromFailure);
  }
#endif

  /* --------------------- Event handlers ------------------------- */

  event result_t MemAlloc.allocComplete(HandlePtr handle, result_t success) {
    Handle *bufList;


	//Handle h = bufList[buf->nextFull];
      if (mState == kIDLE || mState == kREAD_ROW) //not for us
        return SUCCESS; 



      if (success) {
        switch (mState) { 
        case kALLOC_SCHEMA:
	  //need to copy schema over!
	  memcpy (**handle,(char *)mAllocSchema,call ParsedQueryIntf.pqSize(mAllocSchema));
	  //now we have to alloc the memory buffer */
	  mState = kALLOC_BUFFER; 
	  switch (mBuffers[mCurBuffer].type) {
	  case kRAM:
	    if (call MemAlloc.allocate((HandlePtr)&mBuffers[mCurBuffer].u.bufdata, mBuffers[mCurBuffer].len) == FAIL) { 
	      mState = kIDLE;  //error!
	      cleanupBuffer(mCurBuffer, __LINE__);
	      signal DBBuffer.allocComplete(mCurBuffer, err_UnknownError); 
	    } 
	    break;
	  case kEEPROM:
	    //DEBUG("write", 5);
#ifdef kMATCHBOX
	    if (call FileWrite.open(mNamePtr, FS_FCREATE | FS_FTRUNCATE) == FAIL) {
#ifdef kUART_DEBUGGER
	      //	      DEBUG("DBBuf:write open fail", 21);	  
#endif
	      mState = kIDLE;  //error!
	      cleanupBuffer(mCurBuffer, __LINE__);
	      signal DBBuffer.allocComplete(mCurBuffer, err_EepromFailure); 
	    }
#else
	    {
	      //HACK -- this code below to make this somewhat useable on 
	      // PC
	      //cleanupBuffer(mCurBuffer, __LINE__);
	      Buffer *buf = &mBuffers[mCurBuffer];
	      //need to allocate name
	      mState = kALLOC_NAME;
	      buf->u.eeprom.isOpen = TRUE; //mark as open
	      buf->u.eeprom.isWrite = TRUE;
	      if (call MemAlloc.allocate((HandlePtr)&mBuffers[mCurBuffer].name, strlen(mNamePtr) + 1) == FAIL) {
		mState = kIDLE;  //error!
		cleanupBuffer(mCurBuffer, __LINE__);
		signal DBBuffer.allocComplete(mCurBuffer, err_OutOfMemory); 
	      }
	      //signal DBBuffer.allocComplete(mCurBuffer, /*err_EepromFailure*/ err_NoError); 
	    }
#endif
	    break;
	  default:
	    //shouldn't happen!
	    break;
	  }
	  break; 
	case kEEPROM_ALLOC_ROW: {
	  Buffer *buf = &mBuffers[mCurBuffer];

	  call MemAlloc.lock(*handle);
	  call QueryResultIntf.toBytes(mCurResult, *buf->qh, ((char *)**handle) + 1);
	  (**handle)[0] = (char)(call MemAlloc.size(*handle) - 1); //make the first byte a size byte
	  mState = kEEPROM_WRITE;
#ifdef kMATCHBOX
	  if (call FileWrite.append(**handle, call MemAlloc.size(*handle)) == FAIL) {
	    call MemAlloc.unlock(*handle);
	    mState = kIDLE;
	    cleanupBuffer(mCurBuffer, __LINE__);
	    signal DBBuffer.putComplete(mCurBuffer, mCurResult, err_EepromFailure);
	  }
#else
	    call MemAlloc.unlock(*handle);
	    mState = kIDLE;
	    cleanupBuffer(mCurBuffer, __LINE__);
	    signal DBBuffer.putComplete(mCurBuffer, mCurResult, err_EepromFailure);
#endif
	}
	break;
        case kALLOC_BUFFER: 

      	  memset(**handle, 0, mBuffers[mCurBuffer].len); //clear to 0
	  if (mNamePtr != NULL) {
	    mState = kALLOC_NAME;
	    if (call MemAlloc.allocate((HandlePtr)&mBuffers[mCurBuffer].name, strlen(mNamePtr) + 1) == FAIL) {
	      mState = kIDLE;  //error!
	      cleanupBuffer(mCurBuffer, __LINE__);
	      signal DBBuffer.allocComplete(mCurBuffer, err_UnknownError); 
	    }
	  } else {
	    mState = kIDLE; 
#ifdef kDEBUG
	    enqueueResult();
#endif	    
	    mUsedBufs |= (1 << mCurBuffer); 
	    signal DBBuffer.allocComplete(mCurBuffer, err_NoError); 
	  }
	  break; 
	case kALLOC_NAME: 
	  mUsedBufs |= (1 << mCurBuffer); 
	  strcpy(*mBuffers[mCurBuffer].name, mNamePtr);
	  mState = kIDLE;
#ifdef kMATCHBOX
	  if (mBuffers[mCurBuffer].type == kEEPROM) {
	    mAllocing = TRUE;
	    call DBBuffer.writeEEPROMBuffer(mCurBuffer);
	  } else
#endif
	    signal DBBuffer.allocComplete(mCurBuffer, err_NoError);
	  break;
	case kALLOC_ROW: {

	  Buffer *buf = &mBuffers[mCurBuffer];
	  bufList = (Handle *)(*buf->u.bufdata);
	  bufList[mCurRow] = *handle;
	  call MemAlloc.lock(*handle);
	  call QueryResultIntf.toBytes(mCurResult, *buf->qh, (char *)**handle);
	  call MemAlloc.unlock(*handle);
	  mState = kIDLE;

#ifdef kDEBUG
	  readResult();
	  enqueueResult();
#endif
	  signal DBBuffer.putComplete(mCurBuffer, mCurResult, err_NoError);
	}
	break;
#ifdef kMATCHBOX
	case kALLOC_FOR_READ:
	  post readEEPROMRow();
	  break;
	case kHEADER_READ:
	case kWRITE_BUFFER:  //can write buffer while reading header
	  if (mHeaderFileState == kALLOC_NAME || mHeaderFileState == kALLOC_QUERY ||
	      mHeaderFileState == kALLOC_FIELD_DATA) {

	    post loadBufferTask();
	  }
	  break;
#endif
	default:
	  break;
	}
      } else { 

	switch (mState) {
	case kALLOC_BUFFER:
	case kALLOC_SCHEMA:
	case kALLOC_NAME:
	  cleanupBuffer(mCurBuffer, __LINE__);
	  signal DBBuffer.allocComplete(mCurBuffer, err_UnknownError); 
	  break;
	case kALLOC_ROW:
	  //this is bad news -- we should probably abort this query -- for now
	  //just do our best to clean up
	  cleanupBuffer(mCurBuffer, __LINE__);
	  signal DBBuffer.putComplete(mCurBuffer, mCurResult, err_UnknownError);
	  break;
	case kALLOC_FOR_READ:
	  signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_OutOfMemory);
	  break;
#ifdef kMATCHBOX
	case kHEADER_READ:
	case kWRITE_BUFFER: //can write buffer while reading header
	  headerReadFailed(err_OutOfMemory);
	  break;
#endif
	default:
	  break; 
	}
        mState = kIDLE;  //reset state
      }
    
    return SUCCESS;
  }

  event result_t MemAlloc.compactComplete() {
    return SUCCESS;
  }

  event result_t MemAlloc.reallocComplete(Handle handle, result_t success) {
    if (mState != kIDLE && handle == mCurRowHandle)
      return signal MemAlloc.allocComplete(&mCurRowHandle,success);
    else
      return SUCCESS; //not for us
    //return SUCCESS;
  }


  event result_t QueryProcessor.queryComplete(ParsedQueryPtr q) {
      uint8_t bufid; 

      if (call DBBuffer.getBufferId(q->qid, FALSE,  &bufid) == err_NoError) { 
	cleanupBuffer(bufid, __LINE__);
      }  else {
	
#ifdef kMATCHBOX
	TinyDBError err;

	if (q->fromBuffer != kNO_QUERY) { //we're reading from some buffer
	  err = call DBBuffer.getBufferId(q->fromBuffer, q->fromCatalogBuffer, &bufid);
	  if (err == err_NoError) {
	    Buffer *buf = &mBuffers[bufid];

	    if (buf->type == kEEPROM && buf->u.eeprom.isOpen) {
	      if (!buf->u.eeprom.isWrite)
		call FileRead.close();
	      buf->u.eeprom.isOpen = FALSE; //mark as closed
	    }

	  }
	} 
	//we're writing to some buffer
	if (q->bufferType == kEEPROM && q->buf.ram.hasOutput) {
	  Buffer *buf = &mBuffers[q->bufferId];

	  //DEBUG("done query", 10);

	  if (buf->type == kEEPROM && buf->u.eeprom.isOpen) {
	    if (buf->u.eeprom.isWrite)
	      call FileWrite.close();
	    buf->u.eeprom.isOpen = FALSE; //mark as closed
	  }

	}
#endif
      }

	    
      return SUCCESS;
  }

  event result_t CommandUse.commandDone(char *commandName, char *resultBuf, SchemaErrorNo err) {
    return SUCCESS;
  }

  event result_t AttrUse.getAttrDone(char *name, char *resultBuf, SchemaErrorNo errorNo) {
    return SUCCESS;
  }

  event result_t AttrUse.startAttrDone(uint8_t id) {
    return SUCCESS;
  }

#ifdef kMATCHBOX
  //finished opening the eeprom filesystem for writing
  event result_t FileWrite.opened(filesize_t fileSize, fileresult_t result) {
    if (mState == kALLOC_BUFFER && mBuffers[mCurBuffer].type == kEEPROM) {

      if (result == FS_OK) {
	  Buffer *buf = &mBuffers[mCurBuffer];
	//need to allocate name
	mState = kALLOC_NAME;
	buf->u.eeprom.isOpen = TRUE; //mark as open
	buf->u.eeprom.isWrite = TRUE;
	//DEBUG("allname", 8);
	if (call MemAlloc.allocate((HandlePtr)&mBuffers[mCurBuffer].name, strlen(mNamePtr) + 1) == FAIL) {
	  mState = kIDLE;  //error!
	  cleanupBuffer(mCurBuffer, __LINE__);
	  signal DBBuffer.allocComplete(mCurBuffer, err_OutOfMemory); 
	}
      } else { //failure
	mState = kIDLE;
	cleanupBuffer(mCurBuffer, __LINE__);
	signal DBBuffer.allocComplete(mCurBuffer, err_EepromFailure); 
      }
    } else if (mState == kOPEN_BUFFER && mBuffers[mCurBuffer].type == kEEPROM) {
      mState = kIDLE;
      mBuffers[mCurBuffer].u.eeprom.isOpen = TRUE;
      mBuffers[mCurBuffer].u.eeprom.isWrite = TRUE;
      if (result == FS_OK) {
	signal DBBuffer.openComplete(mCurBuffer, err_NoError);
      } else {
	cleanupBuffer(mCurBuffer, __LINE__);
	signal DBBuffer.openComplete(mCurBuffer, err_EepromFailure);
      }
    }
    return SUCCESS;
  }


  //finished writing to the eeprom filesystem
  event result_t FileWrite.appended(void *buffer, filesize_t nWritten, fileresult_t result) {
    call MemAlloc.unlock(mEepromRow);
    mState = kIDLE;

    if (result != FS_OK) { 
      cleanupBuffer(mCurBuffer, __LINE__);
      signal DBBuffer.putComplete(mCurBuffer, mCurResult, err_EepromFailure);
    } else {
      signal DBBuffer.putComplete(mCurBuffer, mCurResult, err_NoError);
    }

    return SUCCESS;
  }

  //finished opening EEPROM file system file
  event result_t FileRead.opened(fileresult_t result) {
    if (result != FS_OK) {
      mState = kIDLE;
      signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_EepromFailure);
    } else {
      post readEEPROMRow();
    }
    return SUCCESS;
  }

  //finished a read from the EEPROM file system
  event result_t FileRead.readDone(void *buffer, filesize_t nRead, fileresult_t result) {
    if (result != FS_OK) {
      
      //DEBUG("fail", 4);
      mState = kIDLE;
      signal DBBuffer.getComplete(mCurBuffer, mCurResult, err_EepromFailure);
    } else {
      post readEEPROMRow();
    }
    return SUCCESS;
  }


  event result_t FileWrite.reserved(filesize_t reservedSize, fileresult_t result) {
    return SUCCESS;
  }

  event result_t FileWrite.synced(fileresult_t result) {
    return SUCCESS;
  }

  event result_t FileWrite.closed(fileresult_t result) {
    //    DEBUG("closed(w)", 9);
    return SUCCESS;
  }

  event result_t FileRead.remaining(filesize_t n, fileresult_t result){
    return SUCCESS;
  }



  //signaled when file system is ready
  event result_t fsReady() {
    mState = kIDLE;
    readFileCount();
    call Leds.yellowToggle();
    return SUCCESS;
  }
#endif

  event bool RadioQueue.enqueueDone() {
    if (mState == kRADIO_ENQUEUE) {
      continueRadioBufferEnqueue(); //try to send the next result, if there is one
      return (mState == kRADIO_ENQUEUE);
    }
    return FALSE;
  }
  
  /* --------------------- Private Routines ------------------------- */

  /** (PRIVATE) Adjust the next free row in the buffer
     @return err_OutOfMemory if the policy indicates that no more inserts should be allowed 
  */

  TinyDBError calcNextFreeRow(Buffer *buf) {
    switch (buf->policy) {
    case EvictOldestPolicy:
      //just a circular buffer

      buf->nextFree++;
      if (buf->nextFree >= buf->numRows) 
	buf->nextFree = 0;

      //if current free reaches head of queue, advance head of queue (which is pointing at oldest element)
      //also deallocate current nextFull item
      if (buf->nextFree == buf->nextFull) {

	//we don't actually dispose of the memory anymore -- instead, we realloc, which can be a lot faster
	/* Handle *bufList = (Handle *)(*buf->u.bufdata);
	   Handle h = bufList[buf->nextFull];
	
	   if (h != NULL) call MemAlloc.free(h);
	   bufList[buf->nextFull] = NULL;
	*/

	buf->nextFull++;
	if (buf->nextFull >= buf->numRows)
	  buf->nextFull = 0;
      }


      break;
    }
    return err_NoError;

  }

  /** (PRIVATE) Return a pointer to buffer bufId in buf if bufId is a valid buf.
     Otherwise, return err_InvalidIndex
  */
  TinyDBError getBuf(uint8_t bufId, Buffer **buf) {
    if (bufId >= kNUM_BUFS)
      return err_IndexOutOfBounds; //unknown schema
    if ((mUsedBufs & (1 << bufId)) == 0)
      return err_InvalidIndex;
    *buf = &mBuffers[bufId];
    return err_NoError;
  }

  /** (PRIVATE) Clean up buffer id b.  Deallocates all associated memory and
      sets the buffer use bits appropriately.  Note that this should
      work even an allocation is partly completed -- it checks for NULL before
      deallocating.
  */
  void cleanupBuffer(int b, int lineNo) {
    //if ((mUsedBufs & (1 << b))) {
    Buffer *buf = &mBuffers[b]; 

    dbg(DBG_USR2, "FREEING BUFFER : %d\n", b);

/*          {   */
/*            char lineStr[5];   */
/*            mDbgBuf[0] = 0;    */
/*            strcat(mDbgBuf, "clean:");    */
/*            itoa(lineNo, lineStr, 10);   */
/*            strcat(mDbgBuf, lineStr);   */
/*            DEBUG(mDbgBuf, strlen(mDbgBuf));    */
/*          }   */

    mUsedBufs &= (0xFFFFFFFF ^ (1 << b)); //mark this buffer as unused 

    if (buf->type == kRAM) { 
      uint16_t i;
      if (buf->u.bufdata != NULL) {
	Handle *bufList = (Handle *)(*buf->u.bufdata);
	for (i = 0; i < buf->numRows; i++) {
	  if (bufList[i] != NULL) {
	    call MemAlloc.free((Handle)bufList[i]);
	  }
	}
	call MemAlloc.free((Handle)buf->u.bufdata); 
      }
    } else if (buf->type == kEEPROM) {
      if (buf->u.eeprom.isOpen) {
	buf->u.eeprom.isOpen = FALSE;
#ifdef kMATCHBOX
	if (buf->u.eeprom.isWrite) {
	  call FileWrite.close(); //close the buffer!
	} else {
	  call FileRead.close();
	}
#endif
      }
      
      if (mEepromRow != NULL) {
	call MemAlloc.free((Handle)mEepromRow);
	mEepromRow = NULL;
      }
    }
    
    if (buf->qh != NULL) {
      call MemAlloc.free((Handle)buf->qh); 
    }
    
    if (buf->name != NULL) {
      call MemAlloc.free((Handle)buf->name);
    }



  }

  //Map from the specified buffer type to an internal buffer
  //id that can be used to get information about fixed schema
  //catalog buffers
  TinyDBError getSpecialBufferId(BufferType type, uint8_t *bufferId) {
    switch (type) {
    case kRADIO:
      *bufferId = kRADIO_BUFFER;
      break;
    case kATTRLIST:
      *bufferId = kATTR_BUF;
      break;
    case kQUERYLIST:
      *bufferId = kQUERY_BUF;
      break;
    case kCOMMANDLIST:
      *bufferId = kCOMMAND_BUF;
      break;
    case kEVENTLIST:
      *bufferId = kEVENT_BUF;
      break;
    default:
      return err_UnsupportedBuffer;
    }
    return err_NoError;
  }
  
#ifdef kUART_DEBUGGER
async  event result_t  UartDebugger.writeDone(char *c, result_t success) {
    return SUCCESS;
  }
#endif

  
}
