// $Id: TinyDB.h,v 1.29 2003/10/07 21:46:21 idgay Exp $

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
/*
 * Authors:	Sam Madden
 *              Design by Sam Madden, Wei Hong, and Joe Hellerstein
 * Date last modified:  6/26/02
 *
 *
 */

/**
 * @author Sam Madden
 * @author Design by Sam Madden
 * @author Wei Hong
 * @author and Joe Hellerstein
 */



uint8_t combine_tdberr(uint8_t r1, uint8_t r2);
typedef uint8_t TinyDBError 
#if NESC >= 110
__attribute__((combine(combine_tdberr)))
#endif
     ;

enum {
  err_NoError = 1,
  err_UnknownError = 0,
  err_OutOfMemory = 2,
  err_UnknownAllocationState = 3,
  err_InvalidGetDataCommand = 4,
  err_InvalidAggregateRecord =5,
  err_NoMoreResults = 6, //no more results this epoch
  err_MessageBufferInUse = 7, //generic message failure due to shared buffer conflict
  err_MessageSendFailed = 8, //generic message failure
  err_RemoveFailedRouterBusy = 9,
  err_MessageBufferFull = 10, //no space in data buffer for data tuple
  err_MSF_DelMsg = 11, //MSF == message send failed , on message deletion
  err_MSF_DelMsgBusy = 12, //message send failed due to radio busy on message deletion
  err_MSF_ForwardKnownQuery = 13, //message send failed while forwarding a known query
  err_MSF_ForwardKnownQueryBusy = 14, // due to radio busy
  err_MSF_ForwardNewQuery = 15, //message send failed while forwarding a new query
  err_MSF_ForwardNewQueryBusy = 16,// due to radio busy
  err_MSF_SendWaiting = 17, //message send failed sending an outgoing data tuple
  err_MSF_SendWaitingBusy = 18,  // due to radio busy
  err_InvalidIndex = 19, //and invalid index was passed to an accessor routine
  err_UnsupportedPolicy = 20, //an unsupported buffer eviction policy was requested
  err_ResultBufferInUse = 21,
  err_ResultBufferBusy = 22,
  err_UnknownCommand = 23,
  err_UnsupportedBuffer = 24,
  err_IndexOutOfBounds = 25,
  err_InvalidQueryId = 26, //specified query id was incorrect
  err_AlreadyTupleResult = 27, //tuple-based query results can't contain aggregate results also
  err_InvalidResultType = 29,
  err_UnknownAttribute = 30,
  err_Typecheck = 31,
  err_NoUnnamedEepromBuffers = 32, //EEPROM BUFFERS MUST HAVE A NAME
  err_EepromFailure = 33,
  err_BufferNotOpen = 34,
  err_BufferOpenForWriting = 35, //the buffer is open for writing
  err_NoMatchbox = 36 //kMATCHBOX is not defined, can't use EEPROM buffers
};

#if NESC >= 110
TinyDBError combine_tdberr(TinyDBError r1, TinyDBError r2) { 
  if (r1 == err_NoError) return r2;
  else return r1;
}

#endif


/* Tuples are always full, but with null compression
   Fields in the tuple are defined on a per query basis,
   with mappings defined by the appropriate query
   data structure.
   If a field is null (e.g. not defined on the local sensor), its
   notNull bit is set to 0.

   Tuples should be accesses exclusively through TUPLE.comp
*/

typedef struct {
  uint8_t qid;  //1
  char numFields; //2
  long notNull;  //bitmap defining the fields that are null or not null //6
  //bit i corresponds to ith entry in ParsedQuery.queryToSchemaFieldMap
  
  char fields[0]; //Access only through TUPLE.comp!
} Tuple, *TuplePtr, **TupleHandle;


enum {QUERY_FIELD_SIZE = 8,
      COMMAND_SIZE = 8,
      STRING_SIZE = 8};

/* Fields are just an 8 character name , plus a transformation operator? */
typedef struct {
  char name[QUERY_FIELD_SIZE]; //8
  uint8_t op; //9
  uint8_t type;//10
  //alias info here?
} Field, *FieldPtr;


/* We can (optionally) invoke a command in response to a query.
   The command may include a single, short parameter.
*/
typedef struct {
  char name[COMMAND_SIZE]; //8
  bool hasParam;  //9
  short param; //11
} CmdBufInfo;

typedef struct {
  bool hasOutput:1;  //is there an output buffer?
  bool hasInput:1;  //is there an input buffer?
  bool create:1; //should this buffer be created, or written to?
  uint16_t numRows:13; //2
  char outBufName[STRING_SIZE];  //10
  char inBufName[STRING_SIZE]; //18
  BufferPolicy policy; //19
} RamBufInfo;

typedef union {
  CmdBufInfo cmd; //11
  RamBufInfo ram; //19
} BufInfo;

typedef struct {
  uint16_t group;
  //  uint8_t len;
  char *data;
} AggResultRef;

enum {
  kMAX_RESULTS = 4,
  AGG_DATA_LEN=28  //WARNING -- this has been picked to fit within the current
                   // message size ...
};

//for now, a query result is really just a tuple
typedef struct QueryResult {
  uint8_t qid; //note that this byte must be qid  //1
  int8_t result_idx; //2
  uint16_t epoch; //4
  uint8_t qrType; //6
  
  uint8_t timeSyncData[5];
  int16_t clockCount;
  int16_t lastDiff;
  union {
    Tuple t; //qrType == kNOT_AGG
    char data[AGG_DATA_LEN]; //qrType == kAGG_SINGLE_FIELD

    //NOTE -- AggResultRefs are used for propagating QueryResults
    // that point into buffers internall, but such results should
    // never be transmitted over the radio (since they contain pointers
    // to internal data structures.
    AggResultRef buf[kMAX_RESULTS]; //pointers for results -- qrType == kIS_AGG
  } d;
  
} QueryResult, *QueryResultPtr;


//stores information about named fields in the query
//see Table/TableM for more information and routines
//to manage this data structure
typedef struct {
  char *data;
  //uint8_t types[1];
  //char* aliases[1];
} QueryTableInfo, **QueryTableHand;

/* Query consists of a list of fields followed by a list of expressions.  Fields are
   a mapping from query fields to local schema fields.  Fields that are in the query
   but not the local schema are defined to be NULL.

   Access variable size parts of this data structure via PQ_ methods defined above
*/
typedef struct {
  uint8_t qid; //1
  uint8_t numFields; //2
  uint8_t numExprs; //3
  uint16_t epochDuration, savedEpochDur; //in millisecs //5
  uint16_t numEpochs; // number of epochs to execute for the query //7
  uint16_t clocksPerSample;
  int16_t clockCount;  //11
  uint16_t currentEpoch; //13
  bool running:1; //14 -- is this query active?
  bool hasAgg:1;  // -- are there aggregates in this query
  bool needsData:1;
  bool hasForClause:1;
  bool hasEvent:4; 

  BufInfo buf; //24 -- output buffer info
  char bufferType; //see Buffer.h:BufferType //25
  uint8_t bufferId; //26 -- output buffer id

  uint8_t fromCatalogBuffer; //if TRUE, fromBuffer is a catalog buffer id (see DBBuffer.h)
  uint8_t fromBuffer; //otherwise we're reading from the specified query buffer (kNO_QUERY == produce results locally) //28

  uint16_t curResult; //what result idx are we currently reading -- 30
  uint8_t markedForDeletion; //if non-zero, number of epochs until we remove this query -- 31
  uint16_t queryRoot; //root of this query -- 34 obsoleted

  uint8_t eventId; //event id that triggers this query -- 36
  uint8_t eventCmdId; //command that is called when this event fires -- 37

  QueryTableHand tableInfo; //39


  //mapping from query field to local schema field id
  char queryToSchemaFieldMap[1]; //access via PQ_GET_FIELD_ID, test for NULL with QUERY_FIELD_IS_NULL // 41
  //offset: sizeof(Query) + (numFields - 1) * sizeof(char)
  //Expr exprs[1];  -- access via PQ_GET/SET_EXPR
  //Tuple t;  -- allocate one tuple per query -- access via PQ_GET_TUPLE
} ParsedQuery, *ParsedQueryPtr;


enum {
  kONE_SHOT = 0x7FFF, //instead of epoch duration, just drain all the results in a buffer
  NULL_QUERY_FIELD = 0x80,
  GROUP_FIELD = 0x7F, //magic code that indicates the value of this
                      //attribute is the aggregate group of a nested query
  TYPED_FIELD = 0x7E, //magic code that indicates the value of this
                      //attribute is just a typed field from a table
};


/* Query gets translated into parsed query by mapping field names into
   local field ids
   
   Access via GET_, SET_ methods described above
   Note that SET_ methods don't set knownFields or knownExprs bitmaps
*/
typedef struct {
  uint8_t qid;
  uint8_t numFields;
  uint8_t numExprs;
  uint8_t fromCatalogBuffer; // what catalog buffer should we read from (0 == use from qid)
  uint8_t fromBuffer; //what queryid should we read from (kNO_QUERY == produce results locally)
  char bufferType; //see Buffer.h:BufferType -- output buffer type
  uint8_t bufferId; //7


  short epochDuration; //in millisecs
  short numEpochs; // number of epochs to execute the queries for
  short knownFields; //bitmask indicating what fields we've seen
  short knownExprs; //bitmask indicating what exprs we've seen //13
  uint16_t queryRoot; // obsoleted

  bool hasBuf; //19
  BufInfo buf; //29

  bool needsEvent; //30
  bool hasEvent; //31
  bool hasForClause; //32
  char eventName[COMMAND_SIZE]; //40

  Field fields[1]; //access via GET_FIELD, SET_FIELD //47
  //Expr exprs[1] //access vis GET_EXPR, SET_EXPR
} Query, *QueryPtr;



enum {
  MAX_FIELDS = 16,
  MAX_EXPRS = 16,
  kNO_QUERY = 0xFF

};

typedef char Op;

enum {
  EQ = 0,
  NEQ = 1,
  GT = 2,
  GE = 3,
  LT = 4,
  LE = 5
};

typedef char Agg;

//field operators, for use in exprs
enum {
  FOP_NOOP = 0,
  FOP_TIMES = 1,
  FOP_DIVIDE = 2,
  FOP_ADD = 3,
  FOP_SUBTRACT = 4,
  FOP_MOD = 5,
  FOP_RSHIFT = 6
};

//expressions are either aggregates or selections
//for now we support the simplest imagineable types (e.g.
//no nested expressions, joins, or modifiers on fields)
typedef struct {
  short field;  //2
  Op op; //3
  short value; //5
} OpValExpr;

typedef struct {
  short field;  //2
  short groupingField;  //field to group on //4
  short groupFieldOp; //6
  short groupFieldConst; //8
  
  Agg op; //9
} AggregateExpression;

typedef struct {
  AggregateExpression agg; //9
  //temporal agg can have at most 4 arguments
  uint8_t args[4];//13
} TemporalAggExpr;

typedef struct {
  Op op; //1
  short field; //3
  char s[STRING_SIZE]; //11
} StringExpr; //11

enum {
  kNO_GROUPING_FIELD = 0xFFFF
};

//operator state represents the per operator
//query state stored in the tuple router and
//sent to the operators on invocation
typedef char** OperatorStateHandle;

enum {
  kSEL = 0,
  kAGG = 1,
  kTEMP_AGG = 2,
};

typedef struct {
  char opType:6;
  bool isStringExp:1; //is this a string expression or not?
  bool success:1; //boolean indicating if this query was successfully applied //1
  char idx; //index of this expression in the query //2

  union {
    OpValExpr opval;
    AggregateExpression agg;
    TemporalAggExpr tagg;
    StringExpr sexp; //for comparisons with strings
  } ex; //15
  short fieldOp; //17 -- from FOP... defines above
  short fieldConst; //19
  
  OperatorStateHandle opState; //21
} Expr, *ExprPtr;


enum {
  kFIRST_RESULT = 0xFF,
  
};

//enums for the QueryResult qrType (what kind of query result)
enum {
  kUNDEFINED = 0,
  kIS_AGG = 1,
  kNOT_AGG = 2,
  kAGG_SINGLE_FIELD = 3
};

typedef struct {
  uint8_t qid; //query this result corresponds to
  bool isAgg; //is this an aggregate result, or a base tuple
  uint16_t epoch; //epoch this result corresponds to
  TinyDBError error; //error flag for return
  union {
    uint16_t tupleField; //which record of this result is this?
    struct {
      int16_t group; //aggregate result group id
      uint8_t id;
      uint8_t len; //and length in bytes
    } agg;
  } u;
  char *data; //the data corresponding to this result
} ResultTuple;

  /* ----------------------- Query Types ------------------------ */

  //queries have to be decomposed into multiple messages
  //these are sent one by one to fill in a query data structure,
  //which is then converted to a parsed query
  

  //in query message -- is this a field or an expression
  enum {
    kFIELD = 0,
    kEXPR =1,
    kBUF_MSG = 2,
    kEVENT_MSG = 3,
    kN_EPOCHS_MSG = 4,
    kDROP_TABLE_MSG = 5
  };

  // type of query message
  enum {ADD_MSG = 0,
	DEL_MSG = 1,
	MODIFY_MSG = 2,
	RATE_MSG = 3,
	DROP_TABLE_MSG = 5
  };

enum {
  CRC_FAILURE = 1, //source of loss for contention monitoring
  ACK_FAILURE = 2,
  SEND_FAILURE = 3,
  ENQUEUE_FAILURE = 4,
  SEND_BUSY_FAILURE = 5
};

//enums for adjust the sample rate based on observed contention
enum {
  HIGH_CONTENTION_THRESH = 20,
  LOW_CONTENTION_THRESH = 10
};

  /** Message type for carrying query messages */
  typedef struct QueryMessage {
    // XXX recompute header size //7
    uint8_t qid; //query id //8 -- note that this byte must be qid
    uint16_t fwdNode; //10 -- node that forwarded the query message
    char msgType;  //type of message (e.g. add, modify, delete q) //11
    char numFields; //12
    char numExprs; //13
    char fromBuffer; //14
    uint8_t fromCatalogBuffer:1; //15
    uint8_t hasEvent:1; //15
    uint8_t hasForClause:1; //15
    uint8_t bufferType:5; //15 -- output buffer type
    short epochDuration; //in millisecs -- 17
    char type;  //is this a field, expression, buffer, or event msg -- 18
    char idx; //19
    uint8_t timeSyncData[5];
    int16_t clockCount;
    union {
      Field field;
      Expr expr; //40
      BufInfo buf;
      char eventName[COMMAND_SIZE];
      short numEpochs;
      int8_t ttl;  //for delete msg
    } u; //40

  } QueryMessage, *QueryMessagePtr;

#ifdef kQUERY_SHARING
  //these messages sent from remote motes requesting a query
typedef struct {
  uint8_t qid; //note that this byte must be query id
  uint32_t qmsgMask; // bit mask for query messages already received
  uint16_t reqNode; // node that is requesting the query, purely for debugging
  uint16_t fromNode; // node to request query from, purely for debugging
} QueryRequestMessage, *QueryRequestMessagePtr;
#endif
 
struct UartMsg {
  char data[30];
};
struct RTCMsg {
  uint32_t time_high32;
  uint32_t time_low32;
};

  /* ----------------------- Status Message ------------------------ */
enum { kMAX_QUERIES = 8 };
typedef struct StatusMessage {
  bool fromBase;
  uint8_t numQueries;
  unsigned char queries[kMAX_QUERIES];
} StatusMessage;

typedef bool *BoolPtr;
typedef char *CharPtr;

enum {
  kDATA_MESSAGE_ID = 240,	// XXX must be one of the amids in lib/Route/MultiHop.h
  kQUERY_MESSAGE_ID = 101, 
  kCOMMAND_MESSAGE_ID = 103,
  kQUERY_REQUEST_MESSAGE_ID = 104,
  kEVENT_MESSAGE_ID = 105,
  kSTATUS_MESSAGE_ID = 106,
  kDIRECTED_DATA_MESSAGE_ID = 107,
  kMSG_LEN = DATA_LENGTH,
  AM_QUERYRESULT = kDATA_MESSAGE_ID,
  AM_QUERYMESSAGE = kQUERY_MESSAGE_ID,
  AM_STATUSMESSAGE = kSTATUS_MESSAGE_ID,
  AM_UARTMSG = 1,
  AM_RTCMSG = 107
};

enum {
	kTINYDB_SERVICE_ID = 0
};

//header information that MUST be in every message
//if it is to be send via TINYDB_NETWORK -- we require
//so that TINYDB_NETWORK doesn't have to copy messages
// this is for TinyDB native network only!!
	typedef struct {
		short senderid; //id of the sender
		short parentid; //id of senders parent
		uint8_t level; //level of the sender
	  //  unsigned char xmitSlots; //number of transmission slots? -- unused now
		unsigned char timeRemaining; //number of clock cyles til end of epoch
	  //    short idx; //message index
	  uint8_t idx;
	} DbMsgHdr;
  typedef struct NetworkMessage {
    DbMsgHdr hdr;
    char data[0];
  } NetworkMessage;

#define isRoot() (TOS_LOCAL_ADDRESS == 0)
