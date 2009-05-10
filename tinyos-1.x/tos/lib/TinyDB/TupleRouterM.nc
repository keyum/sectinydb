// $Id: TupleRouterM.nc,v 1.59 2005/08/14 19:37:59 smadden Exp $

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
includes Attr;
includes MemAlloc;
includes TosTime;
includes TosServiceSchedule;

/**
  The TupleRouter is the core of the TinyDB system -- it receives
  queries from the network, creates local state for them (converts them
  from Queries to ParsedQueries), and then collects results from local
  sensors and neighboring nodes and feeds them through local queries.
<p>
  Queries consist of selections and aggregates.  Results from queries
  without aggregates are simply forwarded to the root of the tree to be
  handled by the query processor.
<p>
  Queries with aggregates are processed according to the TAG approach:
  each node collects partial aggregates from its children, combines
  those aggregates with its own sensor readings, and forwards a partial
  aggregate on to its parents.
<p>
  There are three main execution paths within TUPLE_ROUTER; one for
  accepting new queries, one for accepting results from neighboring
  nodes, and one for generating local results and deliver data to parent
  nodes.
<p>
  QUERY ARRIVAL<p>
  ------------<p>
<p>
  1) New queries arrive in a TUPLE_ROUTER_QUERY_MESSAGE.  Each query
  is assumed to be identified by a globally unique ID.  Query messages
  contain a part of a query: either a single field (attribute) to
  retrieve, a single selection predicate to apply, or a single
  aggregation predicate to apply.  All the QUERY_MESSAGEs describing a
  single query must arrive before the router will begin routing tuples
  for that query.
<p>
  2) Once all the QUERY_MESSAGESs have arrived, the router calls
  parseQuery() to generate a compact representation of the query in
  which field names have been replaced with field ids that can be used
  as offsets into the sensors local catalog (SCHEMA).
  <p>
  3) Given a parsedQuery, the tuple router allocates space at the end
  of the query to hold a single, "in-flight" tuple for that query --
  this tuple will be filled in with the appropriate data fields as the
  query executes.
  <p>
  4) TupleRouter then calls setSampleRate() to start (or restart) the
  mote's 32khz clock to fire at the appropriate data-delivery rate for
  all of the queries currently in the system.  If there is only one
  query, it will fire once per "epoch" -- if there are multiple queries,
  it will fire at the GCD of the delivery intervals of all the queries.
<p>
  TUPLE DELIVERY<p>
  --------------<p><p>
  1) Whenever a clock event occurs (TUPLE_ROUTER_TIMER_EVENT), the
  router must perform four actions:
<p>
  a) Deliver tuples which were completed on the previous clock event
  (deliverTuplesTask).  If the query contains an aggregate, deliver the
  aggregate data from the aggregate operator;  if not, deliver the
  tuple filled out during the last iteration. Reset the counters that
  indicate when these queries should be fired again.
  <p>
  b) Decrement the counters for all queries.  Any queries who's
  counters reach 0 need to have data delivered.  Reset the
  expression specific state for these queries (this is specific
  to the expressions in the queries -- MAX aggregates, for instances,
  will want to reset the current maximum aggregate to some large
  negative number.)
<p>
  c) Fetch data fields for each query firing this epoch.  Loop
  through all fields of all queries, fetch them (using the SCHEMA
  interface), and fill in the appropriate values in the tuples
  on the appropriate queries.
  <p>
  d) Route filled in tuples to query operators.  First route to
  selections, then the aggregate (if it exists).  If any selection
  rejects a tuple, stop routing it.
  <p>
  NEIGHBOR RESULT ARRIVAL<p>
  -----------------------<p>
  <p>
  When a result arrives from a neighbor (TUPLE_ROUTER_RESULT_MESSAGE),
  it needs to be integrated into the aggregate values being computed
  locally.  If the result corresponds to an aggregate query, that result
  is forwarded into the AGG_OPERATOR component, otherwise it is
  simply forwarded up the routing tree towards the root.

  @author Sam Madden (madden@cs.berkeley.edu)
*/

includes Attr;
includes MemAlloc;
includes TinyDB;

module TupleRouterM {

  uses {
    interface Network;
    interface AttrUse;
    interface TupleIntf;
    interface QueryIntf;
    interface ParsedQueryIntf;
    interface Operator as AggOperator;
    interface Operator as SelOperator;
    interface QueryResultIntf;
    interface MemAlloc;
    interface Leds;
    interface AbsoluteTimer;
    interface TimeUtil;
    interface Time;
    interface TimeSet;
    interface StdControl as ChildControl;
    interface StdControl as NetControl;
    interface StdControl as TimerControl;
	interface StdControl as AttrControl;
    interface Random;
#ifdef kUART_DEBUGGER
    interface StdControl as UartDebuggerControl;
#endif
    interface DBBuffer;
    interface CommandUse;
#ifdef kSUPPORTS_EVENTS
    interface EventUse;
#endif
#ifdef kSUPPORTS_EVENTS
    interface CommandRegister as EventFiredCommand;
#endif
#ifdef kLIFE_CMD
    interface CommandRegister as SetLifetimeCommand;
#endif
    interface NetworkMonitor;
    interface Table;
#ifdef kUART_DEBUGGER
    interface Debugger as UartDebugger;
#endif
    interface ServiceScheduler;
    command TinyDBError addResults(QueryResult *qr, ParsedQuery *q, Expr *e);
#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT) || defined(PLATFORM_CRICKET)
    interface RadioCoordinator as RadioSendCoordinator;
    interface RadioCoordinator as RadioReceiveCoordinator;
    command result_t PowerMgmtEnable();
    command result_t PowerMgmtDisable();
#endif
#ifdef HAS_ROUTECONTROL
    interface RouteControl;
#endif
#ifdef USE_WATCHDOG
	interface StdControl as PoochHandler;
	interface WDT;
#endif

    async command void setSimpleTimeInterval(uint16_t new_interval);
    async command uint16_t getSimpleTimeInterval();

    command result_t queryResultHook(uint8_t bufferId, QueryResultPtr r,
				     ParsedQuery *pq);
  }

  provides {
    interface QueryProcessor;
    interface StdControl;
    interface StdControl as ForceAwake;
    interface RadioQueue;
#ifdef HSN_ROUTING
	interface HSNValue;
#endif

    command void signalError(TinyDBError err, int lineNo);
    command void statusMessage(CharPtr m);

  }
}

implementation {
  
  #define TDB_SIG_ERR(errNo) call signalError((errNo), __LINE__)

  /* ----------------------------- Type definitions ------------------------------ */
  /** number of clocks events that dictate size of interval -- every 3 seconds */
#ifndef MS_PER_CLOCK_EVENT
  enum {kMS_PER_CLOCK_EVENT = 64};
#else
  enum {kMS_PER_CLOCK_EVENT = MS_PER_CLOCK_EVENT};
#endif

  enum {UDF_WAIT_LOOP = 100}; //number of times we pass through main timer loop before giving up on a fetch...
  enum {EPOCHS_TIL_DELETION = 5}; //number of epochs we wait before deleting a "ONCE" query

  /* AllocState is used to track what we're currently allocing */
  typedef enum {
    STATE_ALLOC_PARSED_QUERY = 0,
    STATE_ALLOC_IN_FLIGHT_QUERY,
    STATE_RESIZE_QUERY,
    STATE_NOT_ALLOCING,
    STATE_ALLOC_QUERY_RESULT
  } AllocState;
  
  /** Linked list to track queries currently being processed */
  typedef struct {
    void **next;
    ParsedQuery q;
  } *QueryListPtr, **QueryListHandle, QueryListEl;
  
  /** Completion routine for memory allocation complete */
  typedef void (*MemoryCallback)(Handle *memory);

  /** A data structure for tracking the next tuple field to fill
      needed since some fields come from base sensors (attrs), and some
      come from nested queries
  */
  typedef struct {
      bool isAttr;
      bool isNull;
      union {
	  AttrDescPtr attr;
	  uint8_t tupleIdx;
      } u;
  } TupleFieldDesc;
  
  /* ------------------- Bits used in mPendingMask to determine current state ----------------- */
  enum { READING_BIT = 0x0001,  // reading fields for Query from network
         PARSING_BIT = 0x0002, //parsing the query
         ALLOCED_BIT = 0x0004, //reading fields, space is alloced
         FETCHING_BIT = 0x0008, //fetching the value of an attribute via the schema api
	 ROUTING_BIT = 0x0010, //routing tuples to queries
	 DELIVERING_BIT = 0x0020, //deliver tuples to parents
	 SENDING_BIT = 0x0040, //are sending a message buffer
	 AGGREGATING_BIT = 0x0080, //are computing an aggregate result
	 SENDING_QUERY_BIT = 0x0100, //are we sending a query
	 IN_QUERY_MSG_BIT = 0x0200, //are we in the query message handler?

	 SETTING_SAMPLE_RATE_BIT = 0x0400, //are we setting the sample rate
	 SNOOZING_BIT = 0x0800, //are we snoozing 
	 ATTR_STARTING_BIT = 0x1000, // are we starting attributes?
	 OPENING_WRITE_BUF_BIT = 0x2000, //are we opening the write buffer?
	 REMOVING_BIT = 0x4000, //are we removing a query?
	 FORCE_WAKE_BIT = 0x8000 // are we staying awake

  };

#ifndef USE_LOW_POWER_LISTENING
#define qSNOOZE //using snoozing for long epoch durations
#endif
#undef qADAPTIVE_RATE //adapt sample rate based on contention

  //can't snooze when running in simulator!
#if defined(PLATFORM_PC) || defined(PLATFORM_MICA)
 # undef qSNOOZE
#endif 


#ifdef qSNOOZE
  enum {WAKING_CLOCKS = 5120/kMS_PER_CLOCK_EVENT}; //time we're awake between sleeps
#endif

  /* Minimum number of clock ticks per epoch */
  enum {kBASE_EPOCH_RATE = 10};  

#ifdef PLATFORM_PC
  enum {kMAX_WAIT_CLOCKS = 1};
#else
  enum {kMAX_WAIT_CLOCKS = 1024/kMS_PER_CLOCK_EVENT}; // maximum number of clocks to wait before data is sent out...
#endif

  enum {kMIN_SLEEP_CLOCKS_PER_SAMPLE = 1024/kMS_PER_CLOCK_EVENT};

  //enum {kSIMPLE_TIME_SLEEP_INTERVAL = 512};
#ifdef HAS_ROUTECONTROL
	// default automatic route update interval 180 seconds
	enum { DEFAULT_ROUTE_UPDATE_INTERVAL = 180};
#endif


  /* ----------------------------- Module Variables ------------------------------- */

#ifdef kUART_DEBUGGER
  char mDbgMsg[20];
#endif

  TOS_Msg mMsg;
  uint16_t mPendingMask;
  uint8_t mCycleToSend; //cycle number on which we send
  uint32_t mQMsgMask; // bit mask for query msgs that have been received
  QueryListHandle mQs;
  QueryListHandle mTail;
  Query **mCurQuery; //dynamically allocated query handle
  Query *mCurQueryPtr;

  Handle mTmpHandle;


  MemoryCallback mAllocCallback; //function to call after allocation

  uint8_t mFetchingFieldId; //the field we are currently fetching
  char mCurExpr;  //the last operator in curRouteQuery we routed to
  Tuple *mCurTuple; /* The tuple currently being routed (not the same as the tuple in the
		     query, since operators may allocated new tuples!)
		  */
  QueryListHandle mCurRouteQuery; //the query we are currently routing tuples for


  QueryResult mResult, mEnqResult; //result we are currently delivering or enqueueing
  short mFetchTries;
  AllocState mAllocState;

  short mOldRate; //previous clock rate

  QueryListHandle mCurSendingQuery;
  char mCurSendingField;
  char mCurSendingExpr;
  uint32_t mCurQMsgMask;
  TOS_Msg mQmsg;

  bool mTriedAllocWaiting; //tried to create a new query, but allocation flag was true
#ifdef kQUERY_SHARING
  bool mTriedQueryRequest;  //received a request for query from a neighbor, but was buys
#endif

#ifdef qSNOOZE
  bool mAllQueriesSameRate; // just one query running?
#endif

  bool mSendQueryNextClock;
  bool mSendingQuery;
  uint8_t mSendQueryCnt;
  
  char *mResultBuf;

  ParsedQuery *mLastQuery; //last query we fetched an attribute for
  ParsedQuery *mTempPQ;

  uint8_t mCurField;

  //constants for split-phase voltage reading
  //before setting the sample rate based on a lifetime
  //goal
  uint16_t mLifetime;
  uint8_t mCurSampleRateQuery;
  uint16_t mVoltage;

  
#ifdef kLIFE_CMD
  bool mLifetimeCommandPending;
#endif

  uint16_t mNumBlocked; //number of cycles we haven't been able to send over the radio for

  uint16_t mClockCount;
  
  bool mIsRunning ; //have some queries that are running
  bool mStopped ; //service scheduler called "stop"
  bool mRadioWaiting;
  bool mSendingResult;
  uint8_t mCurTupleIdx;

  uint8_t mQidToRemove;
  bool mForceRemove;

  uint8_t mNumAttrs; // number of attributes to start
  
  typedef enum {
    TS_NO = 0,
    TS_QUERY_MESSAGE = 1,
    TS_QUERY_RESULT_MESSAGE = 2
  } TimeStampState;

  TimeStampState mMustTimestamp;
  TOS_MsgPtr mTimestampMsg;
  uint16_t mCurSchedTime;
  norace int16_t mLastDiff;
  
  #define kHEARD_DEC 2
  #define kHEARD_THRESH 10
  uint16_t mLastHeard;
  
  uint8_t mSendFailed;  //number of consecutive sends that have failed
  #define MAX_FAILURES 10 //number of sends that must fail before we reset

  uint8_t mStoppedQid;

  uint8_t mDeliverWait;
  //  uint16_t mOldInterval;

  bool mWaitIsDummy;
  bool mIsFirstStart;

#ifdef HSN_ROUTING
  uint16_t mHSNValue;
  uint16_t mNumMerges;
#endif

  /* ----------------- Functions to modify pending mask --------------------- */
 
  void SET_READING_QUERY() {(mPendingMask |= READING_BIT); (mQMsgMask = 0x0); }
  void UNSET_READING_QUERY() { (mPendingMask &= (READING_BIT ^ 0xFFFF)); (mQMsgMask = 0x0); }
  bool IS_READING_QUERY() { return (mPendingMask & READING_BIT) != 0; }
  
  void SET_PARSING_QUERY() { (mPendingMask |= PARSING_BIT); }
  void UNSET_PARSING_QUERY() { (mPendingMask &= (PARSING_BIT ^ 0xFFFF)); }
  bool IS_PARSING_QUERY() { return (mPendingMask & PARSING_BIT) != 0; }
  
  bool IS_SPACE_ALLOCED() { return (mPendingMask & ALLOCED_BIT) != 0; }
  void UNSET_SPACE_ALLOCED() { (mPendingMask &= (ALLOCED_BIT ^ 0xFFFF)); }
  void SET_SPACE_ALLOCED() { (mPendingMask |= ALLOCED_BIT); }
  
  bool IS_FETCHING_ATTRIBUTE() { return (mPendingMask & FETCHING_BIT) != 0; }
  void UNSET_FETCHING_ATTRIBUTE() { (mPendingMask &= (FETCHING_BIT ^ 0xFFFF)); }
  void SET_FETCHING_ATTRIBUTE() { (mPendingMask |= FETCHING_BIT); }
 
  bool IS_STARTING_ATTRIBUTE() { return (mPendingMask & ATTR_STARTING_BIT) != 0; }
  void UNSET_STARTING_ATTRIBUTE() { (mPendingMask &= (ATTR_STARTING_BIT ^ 0xFFFF)); }
  void SET_STARTING_ATTRIBUTE() { (mPendingMask |= ATTR_STARTING_BIT); }
 
  bool IS_ROUTING_TUPLES() { return (mPendingMask & ROUTING_BIT) != 0; }
  void UNSET_ROUTING_TUPLES() { (mPendingMask &= (ROUTING_BIT ^ 0xFFFF)); }
  void SET_ROUTING_TUPLES() { (mPendingMask |= ROUTING_BIT); }
  
  bool IS_DELIVERING_TUPLES() { return (mPendingMask & DELIVERING_BIT) != 0; }
  void UNSET_DELIVERING_TUPLES() { (mPendingMask &= (DELIVERING_BIT ^ 0xFFFF)); }
  void SET_DELIVERING_TUPLES() { (mPendingMask |= DELIVERING_BIT); }
  
  bool IS_SENDING_MESSAGE() { return (mPendingMask & SENDING_BIT) != 0; }
  void UNSET_SENDING_MESSAGE() { (mPendingMask &= (SENDING_BIT ^ 0xFFFF)); }
  void SET_SENDING_MESSAGE() { (mPendingMask |= SENDING_BIT); }
  
  bool IS_AGGREGATING_RESULT() { return (mPendingMask & AGGREGATING_BIT) != 0; }
  void UNSET_AGGREGATING_RESULT() { (mPendingMask &= ( AGGREGATING_BIT ^ 0xFFFF)); }
  void SET_AGGREGATING_RESULT() { (mPendingMask |= AGGREGATING_BIT); }
  
  bool IS_SENDING_QUERY() { return (mPendingMask & SENDING_QUERY_BIT) != 0; }
  void UNSET_SENDING_QUERY() { (mPendingMask &= ( SENDING_QUERY_BIT ^ 0xFFFF)); }
  void SET_SENDING_QUERY() { (mPendingMask |= SENDING_QUERY_BIT); }
  
  bool IS_IN_QUERY_MSG() { return (mPendingMask & IN_QUERY_MSG_BIT) != 0; }
  void UNSET_IS_IN_QUERY_MSG() { (mPendingMask &= ( IN_QUERY_MSG_BIT ^ 0xFFFF)); }
  void SET_IS_IN_QUERY_MSG() { (mPendingMask |= IN_QUERY_MSG_BIT); }

  bool IS_SETTING_SAMPLE_RATE() { return (mPendingMask & SETTING_SAMPLE_RATE_BIT) != 0; }
  void UNSET_SETTING_SAMPLE_RATE() { (mPendingMask &= ( SETTING_SAMPLE_RATE_BIT ^ 0xFFFF)); }
  void SET_SETTING_SAMPLE_RATE() { (mPendingMask |= SETTING_SAMPLE_RATE_BIT); }

 bool IS_SNOOZING() { return (mPendingMask & SNOOZING_BIT) != 0; }
  void UNSET_SNOOZING() { (mPendingMask &= ( SNOOZING_BIT ^ 0xFFFF)); }
  void SET_SNOOZING() { (mPendingMask |= SNOOZING_BIT); }


  bool IS_FORCE_WAKE() { return (mPendingMask & FORCE_WAKE_BIT) != 0; }
  void UNSET_FORCE_WAKE() { (mPendingMask &= ( FORCE_WAKE_BIT ^ 0xFFFF)); }
  void SET_FORCE_WAKE() { (mPendingMask |= FORCE_WAKE_BIT); }


  bool IS_OPENING_WRITE_BUF() { return (mPendingMask & OPENING_WRITE_BUF_BIT) != 0; }
  void UNSET_OPENING_WRITE_BUF() { (mPendingMask &= ( OPENING_WRITE_BUF_BIT ^ 0xFFFF)); }
  void SET_OPENING_WRITE_BUF() { (mPendingMask |= OPENING_WRITE_BUF_BIT); }


  /* ----------------------------- Prototypes for Internal Routines ------------------------------ */

  void continueQuery(Handle *memory);
  bool addQueryField(QueryMessagePtr qmsg);
  bool allocPendingQuery(MemoryCallback callback, Query *q);
  bool allocQuery(MemoryCallback callback, Query *q);
  void parsedCallback(Handle *memory);
  bool parseQuery(Query *q, ParsedQuery *pq);
  void parsedQuery(bool success);
  void continueParsing(result_t success);
  bool queryComplete(Query q);
  bool reallocQueryForTuple(MemoryCallback callback, QueryListHandle qlh);
  void resizedCallback(Handle *memory);
  void setSampleRate();
  void speedUpSampling();
  void slowDownSampling();
  void finishedOpeningWriteBuffer(ParsedQuery *pq);
  void finishedOpeningReadBuffer(ParsedQuery *pq, uint8_t bufferId);
  void continueFromBufferFetch(TinyDBError err);

  void setRate(uint8_t qid, uint16_t epochDur);

  short gcd(short a, short b);
  bool fetchNextAttr();
  TupleFieldDesc getNextQueryField(ParsedQuery **q);
  QueryListHandle nextQueryToRoute(QueryListHandle curQuery);
  bool routeToQuery(ParsedQuery *q, Tuple *t);
  Expr *nextExpr(ParsedQuery *q);
  bool getQuery(uint8_t qid, ParsedQuery **q);
  void startFetchingTuples();
  void resetTupleState(ParsedQuery *q);
  void fillInAttrVal(SchemaErrorNo errorNo);
  void aggregateResult(ParsedQuery *q, QueryResult *qr, char exprId);
  TinyDBError dequeueMessage(TOS_Msg *msg);
  int chooseQueueVictim(const char *data, int len);

  task void removeQueryTask();
  TinyDBError forwardQuery(QueryMessagePtr qmsg);

  void finishedBufferSetup(ParsedQuery *pq);
  void keepRouting();

  void initConsts();
  void decrementQueryCounter();
  void failedOpeningWriteBuffer(ParsedQuery *pq);

  /* Routines to adjust the sample rate based on
     power consumption.
  */
  void computeRates(uint32_t lifetimeHoursRem,
		    uint32_t curVReading,
		    uint32_t ujSampleCost,
		    uint32_t ujAggCost,
		    uint32_t numMsgs,
		    uint32_t numSamples,
		    uint32_t *epochDur,
		    uint16_t *aggWinSize,
		    uint16_t *vPerDay);

  void updateStatistics(uint16_t deltaV, uint16_t elapsedHours, uint16_t vPerDay);
  void continueSetSampleRate();
  SchemaErrorNo setSampleRateForLifetime(uint8_t qid, uint16_t lifetimeHours);
  void doTimeSync(uint8_t timeSyncData[5], uint16_t clockCount);
  void checkTime();
  void sendDummyQueryResult(uint8_t qid, uint8_t numFields, uint16_t curEpoch);
  TinyDBError sendTuple(ParsedQuery *pq, QueryResultPtr qr, bool *pending);
  result_t outputDone(TOS_MsgPtr msg);
  
  uint16_t max(uint16_t a, uint16_t b) {
    return a<b?b:a;
  }

  void startQueryAttrs(ParsedQuery *pq)
  {
  	short i;
	for (i = 0; i < pq->numFields; i++)
	{
		if (call AttrUse.startAttr(pq->queryToSchemaFieldMap[i]) == FAIL)
			mNumAttrs--; // won't get a startAttrDone in this case
	}
  }

  void startAllQueryAttrs()
  {
	QueryListHandle curq;

	SET_STARTING_ATTRIBUTE();
	// first add up total number of attributes
	for (curq = mQs; curq != NULL; curq = (QueryListHandle)(**curq).next)
	{
        if ((**curq).q.clocksPerSample > 0) //this query is ready to go
			mNumAttrs += (**curq).q.numFields;
	}
	for (curq = mQs; curq != NULL; curq = (QueryListHandle)(**curq).next)
	{
        if ((**curq).q.clocksPerSample > 0) //this query is ready to go
			startQueryAttrs(&((**curq).q));
	}
	if (mNumAttrs == 0)
		UNSET_STARTING_ATTRIBUTE();
  }

  //  void statusMessage(char *m);

  /* Tasks */

  task void deliverTuplesTask();
  task void routeTask();
  task void sendQuery();
  task void fillInTask();
  task void mainTask();
  task void queryMsgTask();

/* -----------------------------------------------------------------------------*/
/* --------------------------------- Functions ---------------------------------*/
/* -----------------------------------------------------------------------------*/

  /** Intialize the tuple router */
  command result_t StdControl.init() {
#ifdef kLIFE_CMD
    ParamList params;
#endif
    // TOSH_MAKE_BOOST_ENABLE_OUTPUT();      // port E pin 4
    // TOSH_CLR_BOOST_ENABLE_PIN();  // set low

#ifdef USE_LOW_POWER_LISTENING
#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT) || defined(PLATFORM_CRICKET)
    if (!isRoot())
      call PowerMgmtEnable();
#endif
#endif
    mPendingMask = 0;
    mCycleToSend = 0;
    atomic {
      mQs = NULL;
    }
    mTail = NULL;
    mCurQuery = NULL;

    mNumBlocked = 0;
    //    mOldInterval = 0;
    mOldRate = 0;
    mFetchTries = 0; //hangs in fetch sometimes -- retry count
    
    mTriedAllocWaiting = FALSE;
#ifdef kQUERY_SHARING
    mTriedQueryRequest = FALSE;
#endif
    
    mSendQueryNextClock = FALSE;
    
    mClockCount = 0;
    
    mAllocState = STATE_NOT_ALLOCING;

    mLastQuery = NULL;

    mIsRunning = FALSE;
    mRadioWaiting = FALSE;
    mSendingResult = FALSE;

    atomic {
      mMustTimestamp = TS_NO;
    }

    initConsts(); //set up constants for sample rate based on lifetime
    
    call ChildControl.init();
    call NetControl.init();
    call TimerControl.init();
#ifdef kUART_DEBUGGER
    if (TOS_LOCAL_ADDRESS != 0)
      call UartDebuggerControl.init();
#endif
#ifdef kLIFE_CMD
    mLifetimeCommandPending = FALSE;
    setParamList(&params, 2, UINT8, UINT16);
    call SetLifetimeCommand.registerCommand("life", VOID, 0, &params);
#endif

    mStopped = TRUE;

    mSendFailed = 0;
    mCurSchedTime = 0;
    mLastDiff = 0;
    mLastHeard = 0;

    mStoppedQid = 0xFF;
#ifdef HSN_ROUTING
	mHSNValue = 20; // XXX 20 is an arbitrary initial value
#endif
	mIsFirstStart = TRUE;
    return SUCCESS;
  }

  command result_t StdControl.start() {

    mNumAttrs = 0;
#ifdef HSN_ROUTING
	mNumMerges = 0;
#endif
    mDeliverWait = 0; //reset xmission wait cycles every time through
    mWaitIsDummy = FALSE;
    UNSET_FETCHING_ATTRIBUTE();
    UNSET_STARTING_ATTRIBUTE();
    UNSET_ROUTING_TUPLES();
    UNSET_AGGREGATING_RESULT();


    //send networking update event
    


    if (!isRoot() || !IS_SNOOZING()) {
      
      call ChildControl.start();
      call NetControl.start();

      //if (mOldInterval != 0)
      //call setSimpleTimeInterval(mOldInterval);


#ifndef USE_LOW_POWER_LISTENING
#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT) || defined(PLATFORM_CRICKET)
      call PowerMgmtDisable();
#endif
#endif
      startAllQueryAttrs();
    }

#ifdef HAS_ROUTECONTROL
	  if (!mIsFirstStart)
		  call RouteControl.manualUpdate();
#endif
	  mIsFirstStart = FALSE;

#ifdef qSNOOZE
    
   if (IS_SNOOZING()) {
	//      UNSET_SNOOZING();
	mStopped = FALSE;

	signal AbsoluteTimer.fired();
    } else {
#else
      mStopped = FALSE;
#endif
      call TimerControl.start();

      if (kMS_PER_CLOCK_EVENT > 64)
	call setSimpleTimeInterval(kMS_PER_CLOCK_EVENT/2);

      
      // mStopped = FALSE;
#ifdef kUART_DEBUGGER
      if (TOS_LOCAL_ADDRESS != 0)
	  call UartDebuggerControl.start();
#endif
      //don't reinitialize this after snooze  
      //call Leds.greenOn();
      //call Leds.redOn(); // Mica2Dots only have red
#ifdef qSNOOZE
    }
#endif

    return SUCCESS;
  }

  command result_t StdControl.stop() {
    QueryListHandle qlh = mQs;
    
    mStopped = TRUE;
    call AbsoluteTimer.cancel(); //???
    checkTime();
    

    if (!isRoot()) {

      //mOldInterval = call getSimpleTimeInterval();
      //call setSimpleTimeInterval(kSIMPLE_TIME_SLEEP_INTERVAL);
    
      if (!IS_FORCE_WAKE())
	{
#ifndef USE_LOW_POWER_LISTENING
#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT) || defined(PLATFORM_CRICKET)
	  call PowerMgmtEnable();
#endif
#endif
	  call Leds.set(0); //all off
	  //call UartDebugger.writeLine("stop",4);
	  call ChildControl.stop();
	  // must leave radio on if there is no query running, or if
	  //we haven't heard from our parent for awhile
	  if (mQs != NULL && !IS_SENDING_MESSAGE() /* ??? */ && mLastHeard
	      <= kHEARD_THRESH) {
	    call NetControl.stop();
	  }
	}
      
      if (IS_SENDING_MESSAGE()) { //???
      	//UNSET_SENDING_MESSAGE();
	outputDone(&mMsg);
      }
      
      if (IS_DELIVERING_TUPLES())
	UNSET_DELIVERING_TUPLES();
    }

    if (mLastHeard > kHEARD_THRESH)
      mLastHeard -= kHEARD_DEC;

    //call TimerControl.stop(); //don't stop the clock!

    //otherwise we'll stop when send is done
    
    //    else
    //      mRadioWaiting = TRUE;


#ifdef qSNOOZE
    // make it so that all queries are at the same point when
    // we wake up
    while (qlh != NULL) {
      (**qlh).q.clockCount = WAKING_CLOCKS;
      qlh = (QueryListHandle)(**qlh).next;
      
    }
#endif


    return SUCCESS;
  }


  command result_t ForceAwake.init() {
    UNSET_FORCE_WAKE();
    return SUCCESS;
  }

  command result_t ForceAwake.start() {
    SET_FORCE_WAKE();
    return SUCCESS;
  }

  command result_t ForceAwake.stop() {
    UNSET_FORCE_WAKE();
    return SUCCESS;
  }

  /* --------------------------------- Query Handling ---------------------------------*/


  task void querySubTask();

  /** Message indicating the arrival of (part of) a query */
  event result_t Network.querySub(QueryMessagePtr qmsg) {
    if (!mSendingQuery) {
      QueryMessagePtr tmpmsg = call Network.getQueryPayLoad(&mQmsg);
      *tmpmsg = *qmsg;
      post querySubTask();
    }
    return SUCCESS;
  }

  task void querySubTask() {
    ParsedQuery *q;
    QueryMessagePtr qmsg = call Network.getQueryPayLoad(&mQmsg);
    bool oldField = TRUE;

    if (qmsg->msgType == DROP_TABLE_MSG) {
      if (IS_IN_QUERY_MSG())
	return;
      SET_IS_IN_QUERY_MSG();
      //call UartDebugger.writeLine("cleaning",8);
#ifdef kMATCHBOX
      call DBBuffer.cleanupEEPROM();
#endif
      if (qmsg->u.ttl-- > 0)
	forwardQuery(qmsg);
      UNSET_IS_IN_QUERY_MSG();
      return;
    } else
    if (qmsg->msgType == RATE_MSG) {
    //is a request to change the rate of an existing query

      if (IS_IN_QUERY_MSG())
	return;

      SET_IS_IN_QUERY_MSG();


      //can't change the rate of a query we know nothing about!
      if (!getQuery(qmsg->qid, &q)) {
	goto done_rate;
      }
      if (qmsg->fwdNode == TOS_UART_ADDR) {
	forwardQuery(qmsg);
      }
      dbg(DBG_USR2, "changing rate to %d\n", qmsg->epochDuration);
      setRate(qmsg->qid, qmsg->epochDuration);
    done_rate:
      UNSET_IS_IN_QUERY_MSG();
      return;

     } else if (qmsg->msgType == DEL_MSG) {
    //is a request to delete an existing query
      ParsedQuery *pq;
	  bool isKnown;

      call Leds.yellowToggle();

      
      if (IS_IN_QUERY_MSG() /*|| IS_REMOVING()*/)
	return;
      
      SET_IS_IN_QUERY_MSG();
      //SET_REMOVING();
      if (getQuery(qmsg->qid, &pq))
	isKnown = TRUE;
      else
	isKnown = FALSE;

      //call Leds.redOn();
      call Leds.greenOn();
      call Leds.yellowOn();
      //can't force -- might be in flight
      mQidToRemove = qmsg->qid;
      mForceRemove = FALSE;
      post removeQueryTask();
      //only forward if we know about the query, or if we're the root

      //qmsg->u.ttl = (qmsg->u.ttl) - 1;
      if (isKnown) {
	forwardQuery(qmsg);
      }
      mStoppedQid = qmsg->qid;

      UNSET_IS_IN_QUERY_MSG();
      return;
    }

    //otherwise, assume its an ADD_MSG, for now
    if (!IS_IN_QUERY_MSG()) {


      if (!getQuery(qmsg->qid, &q)) { //ignore if we already know about this query
	SET_IS_IN_QUERY_MSG();
	mStoppedQid = 0xFF;  //a new query, not one we just stopped
	//go ahead and time synchronize with the sender of this message
	doTimeSync(qmsg->timeSyncData, qmsg->clockCount);

	if (IS_READING_QUERY()) {
	  if (qmsg->qid != (**mCurQuery).qid) {
	    if (IS_SPACE_ALLOCED() || mTriedAllocWaiting) {
	      //query is alloced, but heard about a new one
	      //forget old one
	      if (IS_SPACE_ALLOCED()) {
		UNSET_SPACE_ALLOCED();
		dbg(DBG_USR3, "freeing query in READING_QUERY\n");
		 call MemAlloc.free((Handle)mCurQuery);
	      //mCurQuery 
	       }

	      UNSET_READING_QUERY();
	    } else {
	      mTriedAllocWaiting = TRUE;
	      UNSET_IS_IN_QUERY_MSG();
	      return;
	    }
	  } else if (! IS_SPACE_ALLOCED()) {
	    UNSET_IS_IN_QUERY_MSG();
	    return;
	  }  else {  
	    mTriedAllocWaiting = FALSE;
	    oldField = addQueryField(qmsg);
	  }
	
	  //go ahead and forward this guy on, as long as it's new, or we're the root
	  if (!oldField || qmsg->fwdNode == TOS_UART_ADDR)
	    forwardQuery(qmsg);
	}

	//note that we can fall through from previous clause
	if (!IS_READING_QUERY() /*&& !IS_SENDING_MESSAGE()*/) {
	
	  Query pq;
	  QueryMessagePtr qmsgCopy = call Network.getQueryPayLoad(&mMsg);
	
	
	  SET_READING_QUERY();
	  UNSET_SPACE_ALLOCED();
	  mTriedAllocWaiting = FALSE;
	  pq.qid = qmsg->qid;
	  pq.numFields=qmsg->numFields;
	  pq.numExprs=qmsg->numExprs;
	
	  *qmsgCopy = *qmsg; //save a copy
	  //allocate space for query
	  if (!allocPendingQuery(&continueQuery, &pq)) {
	    UNSET_READING_QUERY(); //barf!
	  }
	}
      }  else if (qmsg->fwdNode == TOS_UART_ADDR)  //forward on if it comes from UART
		forwardQuery(qmsg);
      UNSET_IS_IN_QUERY_MSG();
    }

  }
  
  /** Forward out a query message, setting errors as appropriate if the radio is already
      busy.

      Note, this uses the mMsg module variable.
      @param msg The message to send (a copy is made into mMsg, so the application can overwrite after this call)
      @return err_MSF_ForwardKnownQuery if message send failed, err_MSG_ForwardKnownQueryBusy if radio was busy
  */
  TinyDBError forwardQuery(QueryMessagePtr qmsg) {
    TinyDBError err = err_NoError;

    if (!IS_SENDING_MESSAGE()) {
      QueryMessagePtr qmsgCopy;
      SET_SENDING_MESSAGE();
      qmsgCopy = call Network.getQueryPayLoad(&mMsg);
      *qmsgCopy = *qmsg;
      qmsgCopy->fwdNode = TOS_LOCAL_ADDRESS;
      mMustTimestamp = TS_QUERY_MESSAGE;
      mTimestampMsg = &mMsg;
      post queryMsgTask();
      //if (call Network.sendQueryMessage(&mMsg) != err_NoError) {
      //atomic {
      //mMustTimestamp = TS_NO;
      //}
      //UNSET_SENDING_MESSAGE();
      //err = err_MSF_ForwardKnownQuery;
      //goto done;
      // }
      
    } else
      err = err_MSF_ForwardKnownQueryBusy;

    if (err != err_NoError)
      TDB_SIG_ERR(err);
    return err;

  }
  /** Continuation after query is successfully alloc'ed
      @param memory The newly allocated handle (must to be non-null)
  */
  void continueQuery(Handle *memory) {
    QueryMessage *qmsg = call Network.getQueryPayLoad(&mMsg);
    short i; 

    mCurQuery = (Query **)*memory;
    (**mCurQuery).qid = qmsg->qid;
    (**mCurQuery).numFields=qmsg->numFields;
    (**mCurQuery).numExprs=qmsg->numExprs;
    (**mCurQuery).epochDuration=qmsg->epochDuration;
    (**mCurQuery).fromBuffer = qmsg->fromBuffer;
    (**mCurQuery).fromCatalogBuffer = qmsg->fromCatalogBuffer;
    (**mCurQuery).bufferType = qmsg->bufferType;
    (**mCurQuery).queryRoot = 0; // obsoleted
    (**mCurQuery).knownFields = 0;
    (**mCurQuery).knownExprs = 0;
    (**mCurQuery).needsEvent = qmsg->hasEvent;
    dbg(DBG_USR2, "needsEvent = %d, qms.hasEvent = %d", (**mCurQuery).needsEvent,qmsg->hasEvent);
    (**mCurQuery).hasForClause = qmsg->hasForClause;

    if ((**mCurQuery).bufferType != kRADIO) {
      //special buffer info
      (**mCurQuery).hasBuf = FALSE;
      (**mCurQuery).buf.cmd.hasParam = FALSE;
    }

    (**mCurQuery).hasEvent = FALSE;
  
    dbg (DBG_USR3, "num fields = %d\n", qmsg->numFields);

    for (i = qmsg->numFields; i < MAX_FIELDS; i++)
      (**mCurQuery).knownFields |= (1 << i);
    for (i = qmsg->numExprs; i < MAX_EXPRS; i++)
      (**mCurQuery).knownExprs |= (1 << i);
  
    dbg (DBG_USR3, "completeMask = %x, %x\n",(**mCurQuery).knownFields, (**mCurQuery).knownExprs);

    SET_SPACE_ALLOCED();
    addQueryField(qmsg);

    //now forward the message on
    forwardQuery(qmsg);

  }

  /** Given a query message, add the corresponding
      field or expression to a partially completed query
      @return true iff we already knew about this field
      @param msg The query message
  */
  bool addQueryField(QueryMessagePtr qmsg) {
    bool knewAbout = FALSE;

    if (qmsg->type == kFIELD) {
      call QueryIntf.setField(*mCurQuery, (short)qmsg->idx, qmsg->u.field);
      knewAbout = ((**mCurQuery).knownFields & (1 << qmsg->idx)) != 0;
      (**mCurQuery).knownFields |= (1 << qmsg->idx);
      //dbg (DBG_USR3,"Setting field idx %d\n",qmsg->idx); //fflush(stdout);
    } else if (qmsg->type == kEXPR) {
      qmsg->u.expr.opState = NULL; //make sure we clear this out
      call QueryIntf.setExpr(*mCurQuery, qmsg->idx, qmsg->u.expr);
      //call statusMessage(((char *)*mCurQuery) + 24);
      //dbg (DBG_USR3, "Setting expr idx %d\n",qmsg->idx); //fflush(stdout);
      knewAbout = ((**mCurQuery).knownExprs & (1 << qmsg->idx)) != 0;
      (**mCurQuery).knownExprs |= (1 << qmsg->idx);
    } else if (qmsg->type == kBUF_MSG) {
      knewAbout = (**mCurQuery).hasBuf;
      (**mCurQuery).hasBuf = TRUE;
      (**mCurQuery).buf = qmsg->u.buf;
    } else if (qmsg->type == kEVENT_MSG) {

      knewAbout = (**mCurQuery).hasEvent;
      (**mCurQuery).hasEvent = TRUE;
      strcpy((**mCurQuery).eventName,
	     qmsg->u.eventName);
      dbg(DBG_USR2, "GOT EVENT: %s\n", (**mCurQuery).eventName);
    } else if (qmsg->type == kN_EPOCHS_MSG)
	{
      knewAbout = (**mCurQuery).hasForClause;
      (**mCurQuery).hasForClause = TRUE;
	  (**mCurQuery).numEpochs = qmsg->u.numEpochs;
      dbg(DBG_USR2, "GOT NumEpochs: %d\n", (**mCurQuery).numEpochs);
	}

    if (queryComplete(**mCurQuery)) {
      SET_PARSING_QUERY();

      //allocate a parsed query for this query, initialize it
      dbg(DBG_USR3,"Query is complete!\n");//fflush(stdout);

      //lock this down, since we'll be using it for awhile
      call MemAlloc.lock((Handle)mCurQuery);

      allocQuery(&parsedCallback, *mCurQuery);
    }
    return knewAbout;
  }

  /** Called when the buffer has been allocated */
  void finishedBufferSetup(ParsedQuery *pq) {
    // SET_STARTING_ATTRIBUTE();
    // mNumAttrs += pq->numFields;
    // startQueryAttrs(pq);
    setSampleRate(); //adjust clock rate to be gcd of rate of all queries
    //all done
    UNSET_READING_QUERY();
    UNSET_PARSING_QUERY();
  }

  /** Continuation after parsed query is successfully alloc'ed
      NOTE: after we setup query, need to resize for tuple at end of query...
      @param memory Newly allocated handle for the parsed query
  */
  void parsedCallback(Handle *memory) {
    QueryListHandle h = (QueryListHandle)*memory;  //this has already been allocated
    Expr e;

    //dbg(DBG_USR3,"in parsed callback \n");//fflush(stdout);

    e = call QueryIntf.getExpr(*mCurQuery, 0);
    call MemAlloc.lock((Handle)h);
    dbg(DBG_USR3,"parsing \n");//fflush(stdout);
    mTmpHandle = (Handle)h;
    if (!parseQuery(*mCurQuery, &((**h).q))) { //failure?
      (**h).q.qid = (**mCurQuery).qid;   //cleanup
      //we know it's idle, so force
	  mQidToRemove = (**h).q.qid;
	  mForceRemove = TRUE;
      post removeQueryTask();
      call MemAlloc.unlock((Handle)h);
      call MemAlloc.unlock((Handle)mCurQuery);
      call MemAlloc.free((Handle)mCurQuery);
      UNSET_READING_QUERY();
      UNSET_PARSING_QUERY();
      return;
    } 
  }

  /** Callback routine that indicates parsing is complete */
  void parsedQuery(bool success) {
    QueryListHandle h = (QueryListHandle)mTmpHandle;
    int qid = (**mCurQuery).qid; 
    TinyDBError err = err_NoError;

    //dbg(DBG_USR3,"unlocking \n");//fflush(stdout);
    call MemAlloc.unlock((Handle)h);
    //locked this earlier
    call MemAlloc.unlock((Handle)mCurQuery);
    call MemAlloc.free((Handle)mCurQuery);
    mCurQuery = NULL;
    if (success) {
      dbg(DBG_USR3,"finished, now resizing\n");//fflush(stdout);
      if (reallocQueryForTuple(&resizedCallback, (QueryListHandle)h) == FALSE) {
	err = err_OutOfMemory;
	goto fail;
      }
    } else {
      err = err_UnknownError;
      goto fail;
    }
    
    return;
    
  fail:
    if (err != err_UnknownError) TDB_SIG_ERR(err);

    (**h).q.qid = qid;   //cleanup

    //we know it's idle, so force
    mQidToRemove = qid;
    mForceRemove = TRUE;
    post removeQueryTask();

    UNSET_READING_QUERY();
    UNSET_PARSING_QUERY();
      
  }
  
  /** Continuation after the query is realloced to include space for a tuple
      @param memory Resized parsed query
  */
  void resizedCallback(Handle *memory) {
    QueryListHandle h = (QueryListHandle)*memory;  //this has already been allocated
    ParsedQuery *pq = &((**h).q);
    bool pending = FALSE;
    TinyDBError err = err_NoError;

    dbg(DBG_USR3,"finished with resizing\n");//fflush(stdout);
    

    //set up the output buffer for this query

    switch (pq->bufferType) {
    case kRADIO:
      pq->bufferId = kRADIO_BUFFER;
      break;
    case kRAM: 
    case kEEPROM:
      {
	RamBufInfo *ram = &pq->buf.ram;
	
	//look to see if we're logging to an already created (named) buffer
	if (ram->hasOutput) {
	  mTempPQ = pq;

	  if (strlen(ram->outBufName) != 0 && !ram->create ) {
    
	    //we'll get an error from this call if the buffer doesn't exist
	    err = call DBBuffer.getBufferIdFromName(ram->outBufName,&pq->bufferId);
	    if (err != err_NoError) {
	      //if it doesn't exist, look for it in the header
	      SET_OPENING_WRITE_BUF();
#ifdef kMATCHBOX
	      if (pq->bufferType == kEEPROM) err = call DBBuffer.loadEEPROMBuffer(ram->outBufName);
#else
	      err = err_NoMatchbox;
#endif
	      if (err !=  err_NoError) {
		TDB_SIG_ERR(err);
		goto fail;
	      }  else
		pending = TRUE;
	      
	    }

	    if (!pending) {
	      call DBBuffer.openBuffer(pq->bufferId, &pending);
	    }
	    
	  } else {
	    err = call DBBuffer.nextUnusedBuffer(&pq->bufferId);
	    
	    if (err == err_NoError) {
	      //call UartDebugger.writeLine("CREATE BUF", 10);
	      err = call DBBuffer.alloc(pq->bufferId, pq->bufferType, ram->numRows, ram->policy, pq , ram->outBufName, &pending, 0);
	    }
	  }
	  mTempPQ = pq;
	  //--SRM--
	  // err = call DBBuffer.openBufferForWriting(pq->bufferId, &pending);
	  //next state -- call finishedOpeningBuffer

	  if (!pending) {
	    //call UartDebugger.writeLine("nopending", 9);
	    finishedOpeningWriteBuffer(pq);
	  }
	  return;

	} else {
	  pq->bufferId = kRADIO_BUFFER;
	}
      }
      break;
    case kCOMMAND:
      {
	long cmd_param;
	uint8_t *cmd_buf = (uint8_t *)&cmd_param;
	CommandDescPtr cmd = call CommandUse.getCommand(pq->buf.cmd.name);
	
	if (cmd == NULL) {
	  TDB_SIG_ERR(err_UnknownCommand);
	  goto fail;
	}
	
	cmd_buf[0] = cmd->idx;
	*(short *)(&cmd_buf[1]) = pq->buf.cmd.param;
	
	err = call DBBuffer.nextUnusedBuffer(&pq->bufferId);
	if (err == err_NoError)
	  err = call DBBuffer.alloc(pq->bufferId, kCOMMAND, 0, 0, NULL, NULL, &pending, cmd_param);
	if (err != err_NoError) {
	  TDB_SIG_ERR(err);
	  goto fail;
	}
      }
      break;
    default:
	TDB_SIG_ERR(err_UnknownError);
	goto fail;
    }

    if (!pending) finishedBufferSetup(pq);
    return;

  fail:
    failedOpeningWriteBuffer(pq);
    return;
  }

  /* Called when the write buffer fails to open properly */
  void failedOpeningWriteBuffer(ParsedQuery *pq) {

    
    //we know it's idle, so force
	mQidToRemove = pq->qid;
	mForceRemove = TRUE;
    post removeQueryTask();
    UNSET_READING_QUERY();
    UNSET_PARSING_QUERY();    
  }

  /* Should be called after a RAM or EEPROM buffer has been successfully
     opened for writing. Typechecks the buffer and complete query allocation.
  */
  void finishedOpeningWriteBuffer(ParsedQuery *pq) {

    dbg(DBG_USR2,"TYPECHECKING\n");
    //now, we need to type check the buffer with our schema
    if (!(call ParsedQueryIntf.typeCheck(*(call DBBuffer.getSchema(pq->bufferId)), pq))) {
      //TDB_SIG_ERR(err_Typecheck);
      goto fail;
    } else {
      //call UartDebugger.writeLine("typechecked", 11);
    }
    dbg(DBG_USR2,"TYPECHECKED\n");
    
    finishedBufferSetup(pq);

    return;
  fail:
    failedOpeningWriteBuffer(pq);
    return;
  }

  /** Remove a query from the tuple router

     @param qid The query to remove
     @param success Set TRUE if the query was succesfully removed, FALSE if the query
     couldn't be found or an error occurred.
     @param force Remove this query even if it may be in flight
     @return err_RemoveRouterFailed if router is in a state such that the
     query may be use, err_NoError otherwise.
  */
  task void removeQueryTask() {
    //remove information about the specified query id
    QueryListHandle curq;
    QueryListHandle last = NULL;

    if ((!mForceRemove && (IS_FETCHING_ATTRIBUTE() || IS_ROUTING_TUPLES() || 
			   IS_DELIVERING_TUPLES() || IS_SENDING_MESSAGE()))
	|| IS_STARTING_ATTRIBUTE()) {
      TDB_SIG_ERR(err_RemoveFailedRouterBusy);
      //return;
    }
    
    
    curq = mQs;
    while (curq != NULL) {
      if ((**curq).q.qid == mQidToRemove) {       //this is the one to remove
	//best not remove if we're currently sending out this query!
	if (IS_SENDING_QUERY() && (**mCurSendingQuery).q.qid == (**curq).q.qid) {
	  TDB_SIG_ERR(err_RemoveFailedRouterBusy);
	  return;
	}
	if (last != NULL) {       //not the first element
	  (**last).next = (**curq).next;
	} else {  //the first element
	  atomic {
	    mQs = (QueryListHandle)(**curq).next;
	  }
	}

	if (mTail == curq) //was the last element
	  mTail = last; //ok if this is also the first element, since this will now be NULL
	if (mQs == NULL) { //no more queries, stop the clock!
	  mIsRunning = FALSE;

	  UNSET_SNOOZING(); //new queries will require us to restart scheduling

	  // try to stop the service scheduler
	  call ServiceScheduler.remove(kTINYDB_SERVICE_ID);
	  call AbsoluteTimer.cancel();
	  //call Timer.stop();
	  mOldRate = 0; //clear rate info...
	  
	  if (mStopped) {
	    call StdControl.start();
	  }

	  mStopped = TRUE;
	  
#ifdef HAS_ROUTECONTROL
	  // enable automatic route updates by routing layer
	  call RouteControl.setUpdateInterval(DEFAULT_ROUTE_UPDATE_INTERVAL);
#endif

	  call Leds.redOff();
	  call Leds.yellowOff();
	  call Leds.greenOff();
	} 

#ifdef kSUPPORTS_EVENTS
	//delete correspondance between the command and event
	//NOTE: we don't delete the command here -- command interface will allow us to
	// redefine this command id later, so let's not worry about it
	if ((**curq).q.hasEvent) {

	  EventDescPtr e = call EventUse.getEventById((**curq).q.eventId);
	  CommandDescPtr c = call CommandUse.getCommandById((**curq).q.eventCmdId);
	  if (e != NULL && c != NULL) {
	    dbg(DBG_USR2, "Removing correspondance between event %s and command %s\n", e->name, c->name);
	    call EventUse.deleteEventCallback(e->name, c->name);
	    
	  }
	}
#endif

	//notify children (e.g. AGG_OPERATOR) that this query is complete
	dbg(DBG_USR2,"ENDING QUERY : %d\n", (**curq).q.qid);
	signal QueryProcessor.queryComplete(&(**curq).q);
#ifdef HSN_ROUTING
	mHSNValue = 20; // reset to initial value, XXX again 20 is arbitrary
#endif
	if (curq == mCurRouteQuery)
	  mCurRouteQuery=NULL;
	call MemAlloc.free((Handle)curq);
	return;
      } else {
	last = curq;
	curq = (QueryListHandle)(**curq).next;
      }
    }
  }

  /** Send mCurSendingQuery to a neighbor (we assume the query is in
   mCurSendingQuery because the sending must be done in multiple phases)
  */
  task void sendQuery() {
    //this task assembles the query one field / attribute at a time,
    //send each out in a separate radio message (just like they are delivered).
    //task is resceduled after SEND_DONE_EVENT fires
    QueryListHandle curq = mCurSendingQuery;
    QueryMessage *qmsg = call Network.getQueryPayLoad(&mQmsg);

    mSendingQuery=FALSE;
    if (curq == NULL) {
      UNSET_SENDING_QUERY();
      return;
    }

    //NOTE -- we don't current share queries that aren't over the base
    //sensor data!
    if ((**curq).q.fromBuffer != kNO_QUERY) {
      UNSET_SENDING_QUERY();
      return;
    }

	// find the next requested query message
	while (mCurSendingField < (**curq).q.numFields &&
		   (mCurQMsgMask & (1 << mCurSendingField)))
		mCurSendingField++;
    if (mCurSendingField < (**curq).q.numFields) {
      char fieldId = call ParsedQueryIntf.getFieldId(&(**curq).q, (short)mCurSendingField);

      qmsg->msgType = ADD_MSG;
      qmsg->qid = (**curq).q.qid;

      qmsg->numFields = (**curq).q.numFields;
      qmsg->numExprs = (**curq).q.numExprs;
      qmsg->fromBuffer = (**curq).q.fromBuffer;
      qmsg->fromCatalogBuffer = (**curq).q.fromCatalogBuffer;
      qmsg->hasForClause = (**curq).q.hasForClause;
      qmsg->epochDuration = (**curq).q.epochDuration;
      qmsg->bufferType = (**curq).q.bufferType;
      qmsg->fwdNode = TOS_LOCAL_ADDRESS;

      mCurSendingField++;
      if (!(call ParsedQueryIntf.queryFieldIsNull(fieldId))) {
	AttrDescPtr attr = call AttrUse.getAttrById(fieldId);

	qmsg->type = kFIELD;
	qmsg->idx = mCurSendingField-1;
	strcpy(qmsg->u.field.name, attr->name);
	
	call Leds.greenToggle();

	if (!IS_SENDING_MESSAGE()) {
	  SET_SENDING_MESSAGE();
	
	  atomic {
	    mMustTimestamp = TS_QUERY_MESSAGE;
	    mTimestampMsg = &mQmsg;
	  }
	  if (call Network.sendQueryMessage(&mQmsg) != err_NoError) {
	    UNSET_SENDING_MESSAGE();
	    atomic {
	      mMustTimestamp = TS_NO;
	    }
		mSendingQuery = TRUE;
	  	post sendQuery(); // try the next field
	  }
	}

      } else {
	//field is null (we don't know what it's name should be) -- do the next one
	mSendingQuery = TRUE;
	post sendQuery();


      }
    } else {
		// find the next requested query message
		while (mCurSendingExpr < (**curq).q.numExprs &&
		       (mCurQMsgMask & (1 << ((**curq).q.numFields + mCurSendingExpr))))
			mCurSendingExpr++;
		if (mCurSendingExpr < (**curq).q.numExprs) {
		  Expr e = call ParsedQueryIntf.getExpr(&(**curq).q, mCurSendingExpr);
		  mCurSendingExpr++;

		  qmsg->type = kEXPR;
		  qmsg->idx = mCurSendingExpr-1;
		  qmsg->u.expr = e; //this could be bad! (extra bytes on end of expression might overwrite memory)

		  //call Leds.redToggle();

		  if (!IS_SENDING_MESSAGE()) {
		SET_SENDING_MESSAGE();
		atomic {
		  mMustTimestamp = TS_QUERY_MESSAGE;	
		  mTimestampMsg = &mQmsg;
		}
		if (call Network.sendQueryMessage(&mQmsg) != err_NoError) {
		  UNSET_SENDING_MESSAGE();
		  atomic {
			mMustTimestamp = TS_NO;
		  }
		  mSendingQuery = TRUE;
		  post sendQuery(); //try the next field;
		}
		  }
	//send the command that should be invoked in response to this query
		} else if ((**curq).q.bufferType != kRADIO && 
			   mCurSendingExpr == (**curq).q.numExprs &&
			   !(mCurQMsgMask & (1 << ((**curq).q.numFields + (**curq).q.numExprs)))) { 
		  qmsg->type =  kBUF_MSG;
		  qmsg->u.buf = (**curq).q.buf;
		  mCurSendingExpr++;

		  call Leds.yellowToggle();

		  if (!IS_SENDING_MESSAGE()) {
		SET_SENDING_MESSAGE();
		
		if (call Network.sendQueryMessage(&mQmsg) != err_NoError)
		  UNSET_SENDING_MESSAGE();
		  UNSET_SENDING_QUERY();
		  }


		}
		else {
		  UNSET_SENDING_QUERY();
		}
	}
    
  
  }

#ifdef kQUERY_SHARING
  /** Message indicating neighbor requested a query from us 
      If we know about the query, and aren't otherwise
      occupied with sending / routing, send the query back

      @param The QueryRequestMessage from the neighbor
   */
  event result_t Network.queryRequestSub(QueryRequestMessagePtr qmsg) {
    char qid = qmsg->qid;

    QueryListHandle curq;
  
    //if we're already sending this query, ignore duplicate
    //requests...
    if (IS_SENDING_QUERY() && mCurSendingQuery && mSendQueryCnt < 5) {
      if (qid == (**mCurSendingQuery).q.qid)
	return SUCCESS;
    }

	mSendQueryCnt = 0;


    //triedQueryRequest flag set to true when a neighbor requests a
    //query but we're sending another one

    //if we get another such request, we'll abort the current one (ick)
    if (!IS_SENDING_MESSAGE() && (!IS_SENDING_QUERY() || mTriedQueryRequest)) {
      mTriedQueryRequest = FALSE;
      mCurSendingQuery = NULL;
      SET_SENDING_QUERY();
    } else {
      mTriedQueryRequest = TRUE;
      return SUCCESS;
    }
  

    curq = mQs;
    while (curq != NULL) {

      if ((**curq).q.qid == qid) {
	//the query we're supposed to send
	mCurSendingField = 0;
	mCurSendingExpr = 0;
	mCurSendingQuery = curq;
	mCurQMsgMask = qmsg->qmsgMask;
			mSendingQuery = TRUE;
	post sendQuery();

	break;
      }
      curq = (QueryListHandle)(**curq).next;
    }

    if (!mCurSendingQuery) UNSET_SENDING_QUERY();
  
    return SUCCESS;
  }
#endif

  // return a bit vector representing the query messages that have already
  // be received for query sharing.  This avoids repeatedly sending all query
  // messages for sharing
  static uint32_t getQueryMsgMask()
  {
	uint32_t mask = 0;
  	if (IS_READING_QUERY()) {
		QueryPtr q = *mCurQuery;
		short i;
		mask = q->knownFields;
		mask |= (q->knownExprs << q->numFields);
		if (q->bufferType != kRADIO && q->hasBuf)
			mask |= (1 << (q->numFields + q->numExprs));
		else
			mask &= ~(1 << (q->numFields + q->numExprs));
		// clear the rest of the bits
		for (i = q->numFields + q->numExprs + 1; i < 32; i++)
			mask &= ~(1 << i);
	}
	return mask;
  }

  task void queryMsgTask() {
    if (call Network.sendQueryMessage(&mMsg) != err_NoError) {
      UNSET_SENDING_MESSAGE();
      atomic {
	mMustTimestamp = TS_NO;
      }

    }
  }

  /** A message not directly addressed to us that we overhead
      Use this for time synchronization with our parent, and
      to snoop on queries.

      @param msg The message
      @param amId The amid of the message
      @param isParent If the message is from our parent
  */
  event result_t Network.snoopedSub(QueryResultPtr qrMsg, bool isParent, uint16_t senderid) {
    ParsedQuery *q;
    uint8_t qid;
    QueryRequestMessage *qreq = call Network.getQueryRequestPayLoad(&mMsg);
    //check and see if it has information about a query we haven't head before
    //don't snoop on queries from the root (it wont reply)!

#ifdef kQUERY_SHARING
    //if (senderid != 0) {

    call Leds.greenToggle();

      qid = call QueryResultIntf.queryIdFromMsg(qrMsg);
      //is this a query we've never heard of before?

      if (!getQuery(qid, &q) && qid != mStoppedQid) {
	if (!IS_SENDING_MESSAGE()) {
#if 1
	  static uint32_t lasttime;
	  uint32_t now = call Time.getLow32();

	  if (now - lasttime > 10000)
#endif
	    {
	      lasttime = now;
	      SET_SENDING_MESSAGE();
	      qreq->qid = qid;
	      qreq->qmsgMask = getQueryMsgMask();
	      //post queryMsgTask();

	      if (call Network.sendQueryRequest(&mMsg, senderid) != err_NoError)
		UNSET_SENDING_MESSAGE();
	    }
	}
	
      } else if (qid == mStoppedQid) {
	//send a cancel message
	QueryMessage *qm = call Network.getQueryPayLoad(&mMsg);

	//if (!IS_SENDING_MESSAGE()) {
	  SET_SENDING_MESSAGE();
	  qm->qid = qid;
	  qm->msgType = DEL_MSG;	
	  call Leds.yellowToggle();
	  post queryMsgTask();

	  //if (call Network.sendQueryMessage(&mMsg) != err_NoError)
	  //  UNSET_SENDING_MESSAGE();
	}
	
      //}
      
      //}
#endif

    //did this message come from our parent?

    if (isParent || senderid == 0) {
      QueryResult qr;

      //epoch sync with parent
      qid = call QueryResultIntf.queryIdFromMsg(qrMsg);


      if (getQuery(qid, &q)) {
	call QueryResultIntf.fromBytes(qrMsg, &qr, q);

	if (qr.epoch > q->currentEpoch + 1) //make sure epoch is monotonically increasing;  off by one OK?
	 q->currentEpoch = qr.epoch;
      }

      //sync with parent
      doTimeSync(qrMsg->timeSyncData, qrMsg->clockCount);

      // Each node now estimates its local neighborhood size (so we don't do the following)
      //      mNumSenders = hdr->xmitSlots;

      mLastHeard = 0;
    }
  
    return SUCCESS;
  }

  /* --------------------------------- Tuple / Data Arrival ---------------------------------*/

  /** Continue processing a tuple  after a selection operator
      Basically, if the tuple passed the selection, we continue routing it to
      additional operators.  Otherwise, we move on to the next query for routing.
   @param t The tuple that has been processed by the operator,
   @param q The query that this tuple belongs to
   @param e The expression that processed the tuple
   @param passed Indicates whether the tuple passed the operator --
   if not, the tuple should not be output.
   @return err_NoError
*/

  event TinyDBError SelOperator.processedTuple(Tuple *t,
					ParsedQuery *q,
					Expr *e,
					bool passed)
    {
      if (!passed) {
	e->success = FALSE;
	mCurRouteQuery = nextQueryToRoute(mCurRouteQuery);
      }
      post routeTask();
      return err_NoError;
    }

  event TinyDBError SelOperator.processedResult(QueryResult *qr, ParsedQuery *q, Expr *e) {
      return err_NoError; //not implemented
  }

  /** Continue processing a tuple after an aggregation operator has been applied
      @param t The tuple passed into the operator
      @param q The query that the tuple belongs to
      @param e The expression that processed the tuple
      @param passed (Should be true for aggregates)
  */
  event TinyDBError AggOperator.processedTuple(Tuple *t, ParsedQuery *q,
					 Expr *e, bool passed)
    {
      post routeTask();
      return err_NoError;
    }

  /** Called every time we route a query result through an aggregate operator.
      @param qr The query result we processed
      @param q The query it belongs to
      @param e The expression that processed it
      
      Need to route to the next aggregation operator.
  */
  event TinyDBError AggOperator.processedResult(QueryResult *qr, ParsedQuery *q, Expr *e) {
    //maybe unset a status variable?

    aggregateResult(q, qr, e->idx+1);
    return err_NoError;
  }


  /** Received a result from a neighbor -- need to
      either:<p>
      
      1) process it, if is an aggregate result<p>
        or<p>
      2) forward it, if it is a non-aggregate result<p>
      @param msg The message that was received
  */
  event result_t Network.dataSub(QueryResultPtr qrMsg) {
    QueryResult qr;
    ParsedQuery *q;
    bool gotAgg = FALSE;
    bool pending;


    // call Leds.greenToggle();


    if (getQuery(call QueryResultIntf.queryIdFromMsg(qrMsg), &q)) {
      //if this query is going to be deleted, reset the counter until
      //deletion since we're still hearing neighbors results about it...
      dbg(DBG_USR2, "Got query result for query %d\n", q->qid);

      if (q->markedForDeletion) {
	q->markedForDeletion = EPOCHS_TIL_DELETION;
      }
      call QueryResultIntf.fromBytes(qrMsg, &qr, q);
      //now determine where to route this result to -- either an
      //aggregation operator or to our parent

      gotAgg = q->hasAgg;

      if (!gotAgg) { //didn't give to an aggregate, so just pass it on...
	TinyDBError err;
	dbg(DBG_USR2, "forwarding result for query %d to buffer %d\n", q->qid, q->bufferId);

	mEnqResult = *(QueryResultPtr)qrMsg;
	err = call DBBuffer.enqueue(q->bufferId, &mEnqResult, &pending, q);
	// mSendingResult = FALSE; // if this is true after enqueue, we'll 
	                        // post the sendTuplesTask when send finishes, which we 
	                        // may not want to do
	//ignore result buffer busy items for now, since they just mean
	//we can't keep up with the sample rate the user is requested , but we
	//shouldn't abort
	if (err != err_ResultBufferBusy && err != err_NoError) TDB_SIG_ERR(err);
      } else { //got an agg -- do all the aggregation expressions
	mResult = qr;
#ifdef HSN_ROUTING
	mNumMerges++;
#endif
	if (!IS_AGGREGATING_RESULT()) //don't double aggregate!
	  aggregateResult(q, &mResult, 0);
      }
    } 

    return SUCCESS;
  }

  default command result_t queryResultHook(uint8_t bufferId, QueryResultPtr r,
					   ParsedQuery *pq) {
    return SUCCESS;
  }

  /** Apply all aggregate operators to this result.
    Apply them one after another, starting with exprId.
    <p>
    This is called from TUPLE_ROUTER_RESULT_MESSAGE and from
    AGGREGATED_RESULT_EVENT
    @param q The query that the result applies to
    @param qr The query result
    @param exprID The expression to apply to qr

*/
  void aggregateResult(ParsedQuery *q, QueryResult *qr, char exprId) {
    Expr *e;

    if (exprId >= q->numExprs) { //no more aggregation expressions
      UNSET_AGGREGATING_RESULT();
      return;
    }

    e = call ParsedQueryIntf.getExprPtr(q,exprId);
    if (e->opType != kSEL) {
      SET_AGGREGATING_RESULT();
      if (call AggOperator.processPartialResult(qr, q, e) != err_NoError) {
	UNSET_AGGREGATING_RESULT(); //error, just do the next one
	//(errors may just mean the result doesn't apply to the agg)
	aggregateResult(q,qr,exprId+1);
      }
    } else
      aggregateResult(q,qr,exprId+1); //move on to the next one
  }



  /* --------------------------------- Timer Events ---------------------------------*/

  /** Adjust the rate that the main tuple router clock fires at based
      on EPOCH DURATION of all of the queries that are currently installed
  */
  void setSampleRate() {
    QueryListHandle qlh;
    short rate = -1;
	uint16_t minEpochDur = (uint16_t)65535L;

    //walk through queries, choose lowest sample rate
/*      qlh = mQs; */
/*      while (qlh != NULL) { */
/*        if (rate == -1)  */
/*  	rate = (**qlh).q.epochDuration; */
/*        else  */
/*  	rate = gcd((**qlh).q.epochDuration,rate); */
/*        qlh = (QueryListHandle)(**qlh).next; */
/*      } */
  
/*      //throttle rate to maximum */
/*      if (rate <= MIN_SAMPLE_RATE) { */
/*        //    rate = gcd(MIN_SAMPLE_RATE,rate); */
/*        rate = MIN_SAMPLE_RATE; */
/*      } */
/*      dbg(DBG_USR3,"rate = %d\n", rate); //fflush(stdout); */


  
    //HACK
    
    rate = kMS_PER_CLOCK_EVENT; //hardcode!
    //now set the rate at which we have to deliver tuples to each query
    //as a multiple of this rate
    qlh = mQs;

#ifdef qSNOOZE
    //check to see if the new query is the only query or is exactly
    //the same rate as the previous queries
    if ((qlh != NULL && (**qlh).next == NULL) ||
	(qlh != NULL && mAllQueriesSameRate && (**((QueryListHandle)(**qlh).next)).q.epochDuration == (**qlh).q.epochDuration)) {
      mAllQueriesSameRate = TRUE;
    } else
      mAllQueriesSameRate = FALSE;
#endif

    while (qlh != NULL) {
      if ((**qlh).q.epochDuration == kONE_SHOT) { //read it fast!
	(**qlh).q.clocksPerSample = 16;
	(**qlh).q.curResult = 0;
      } else
	(**qlh).q.clocksPerSample = (uint16_t)((((uint32_t)(**qlh).q.epochDuration * kBASE_EPOCH_RATE) / (uint32_t)rate));
	  if ((**qlh).q.epochDuration < minEpochDur)
	  	minEpochDur = (**qlh).q.epochDuration;
      

      atomic {
	//if (mQueryClockCount != 0) {
	//(**qlh).q.clockCount = mQueryClockCount;
	//mQueryClockCount = 0;
	//} else {
#ifdef qSNOOZE 
	if ((**qlh).q.clocksPerSample > WAKING_CLOCKS) {
	  (**qlh).q.clockCount = WAKING_CLOCKS;
	} else {
#endif
	  (**qlh).q.clockCount = (**qlh).q.clocksPerSample; //reset counter
#ifndef qSNOOZE
	  mStopped = FALSE; //hack so that queries start
	                    // running again when snoozing
	                    // is disabled
#endif

#ifdef qSNOOZE 
	}	
#endif
	
	//}
      }


      qlh = (QueryListHandle)(**qlh).next;
    }
	// set route update interval to be twice of epoch duration
    call RouteControl.setUpdateInterval((uint16_t)((uint32_t)minEpochDur * kBASE_EPOCH_RATE / 1024L));
#ifdef USE_WATCHDOG
	call PoochHandler.stop();
	call PoochHandler.start();
	call WDT.start((uint32_t)minEpochDur * kBASE_EPOCH_RATE * 20L);
#endif



  if (rate != mOldRate) { //restart the clock if rate changed
      // tos_time_t cur_time = call Time.get();
      // uint32_t distFromPrev;

      mOldRate = rate;
      mIsRunning = TRUE;


      signal AbsoluteTimer.fired();

    }

  }

  /** Find the GCD of two non-negative integers
      @param a The first integer
      @param b The secnd integer
      @return the GCD of a and b
  */
  short gcd(short a, short b) {
    short r = -1, temp;

    if (a > b) {
      temp = a;
      a = b;
      b = temp;
    }
  
    while (TRUE) {
      r = b % a;
      if (r == 0) break;
      b = a;
      a = r;
    }

    return a;
  }

  
  /** Set the EPOCH DURATION of the specified query to the specifed value.
      @param qid The query that needs its sample rate adjusted
      @param epochDur The new epoch duration for qid
   */

  void setRate(uint8_t qid, uint16_t epochDur) {
    ParsedQuery *q;
    if (getQuery(qid, &q)) {
      q->clocksPerSample = (uint16_t)((((uint32_t)epochDur * kBASE_EPOCH_RATE) / (uint32_t)mOldRate));

    }
  }
  
  /** Make all queries sample less frequently
   Note: We guarantee that slowDownSampling(); speedUpSampling(); will leave
   the sample rate unchanged.
  */
  void slowDownSampling() {
    QueryListHandle qlh = mQs;
    while (qlh != NULL) {
      (**qlh).q.clocksPerSample += kBASE_EPOCH_RATE;
      qlh = (QueryListHandle)(**qlh).next;
    }

  }

  /** Make all queries sample more frequently */
  void speedUpSampling() {
    QueryListHandle qlh = mQs;
    while (qlh != NULL) {
      if ((**qlh).q.clocksPerSample > 1)
	(**qlh).q.clocksPerSample -= kBASE_EPOCH_RATE;
      qlh = (QueryListHandle)(**qlh).next;
    }

  }

  /** Compute the appropriate sample rate .. */

  
  enum {
    msXmit = 32,
    mahCapacity = 5800,
    maxVReading = 985,
    minVReading = 370,
    Vdraw = 3,
    sPerSample = 1

  };

  
  uint32_t uaActive, uaXmit, uaSleep;

  void initConsts() {
    uaActive = 16900;
    uaXmit = 17320;
    uaSleep = 220;
  }

void computeRates(uint32_t lifetimeHoursRem,
		    uint32_t curVReading,
		    uint32_t ujSampleCost,
		    uint32_t ujAggCost,
		    uint32_t numMsgs,
		    uint32_t numSamples,
		    uint32_t *epochDur, //on exit, appropriate epoch duration
		    uint16_t *aggWinSize, //on exit, aggregate window size
		    uint16_t *mvPerDay  // on exit, number of raw voltage units that we expect to consume per day
		    ) {

    uint32_t ujXmitCost= ((uaXmit * msXmit * Vdraw))/(1000);
    uint32_t mahRemaining = ((curVReading - minVReading)* mahCapacity)/(maxVReading - minVReading);
    uint32_t uaAvg = ((mahRemaining * 1000)/lifetimeHoursRem);
    uint32_t uaAvgActive = (ujSampleCost*numSamples + ujXmitCost*numMsgs + ujAggCost*numSamples)/(Vdraw * sPerSample) + uaActive;
    uint32_t dutyCycle = ((uaAvg - uaSleep)*100000)/(uaAvgActive - uaSleep);

    if (uaAvg < uaSleep)
      *epochDur = -1;
    else {
      *epochDur = (sPerSample * 100000 * 1000)/(dutyCycle);
      if (*epochDur < sPerSample * 1000)
	*epochDur = sPerSample * 1000;
    }
    dbg(DBG_USR2, "epoch dur set to %d", *epochDur);
    *aggWinSize = 1;
    *mvPerDay = ((curVReading - minVReading)*24*1000)/(lifetimeHoursRem);
    //note that this assumes we don't do any reduction in communication via aggregation
    
  }

  void updateStatistics(uint16_t deltaV, uint16_t elapsedHours, uint16_t mvPerDay) {
    uint16_t actualVPerDay = (deltaV * 24)/(elapsedHours);
    uint16_t ratio = (mvPerDay * 100 )/ (actualVPerDay * 1000);
    uaActive = (uaActive * 100)/ratio;
    uaXmit  = (uaXmit * 100)/ratio;
    uaSleep = (uaSleep * 100)/ratio;
    dbg(DBG_USR2, "new uaActive = %d, uaXmit = %d, uaSleep = %d\n", uaActive, uaXmit, uaSleep);
  }

  SchemaErrorNo setSampleRateForLifetime(uint8_t qid, uint16_t lifetimeHours) {
    SchemaErrorNo errNo;

    errNo = SCHEMA_SUCCESS;
    if (IS_SETTING_SAMPLE_RATE()) {
      errNo = SCHEMA_ERROR;
      goto done;
    }

    SET_SETTING_SAMPLE_RATE();

    mLifetime = lifetimeHours;
    mCurSampleRateQuery = qid;

#if !defined(PLATFORM_PC)
    if (call AttrUse.getAttrValue("voltage", (char *)&mVoltage, &errNo) == FAIL) {
      errNo = SCHEMA_ERROR;
      goto fail;
    }
    if (errNo == SCHEMA_SUCCESS)
      continueSetSampleRate();
    else if (errNo != SCHEMA_RESULT_PENDING)
      goto fail;
#else
    mVoltage = 900;
    continueSetSampleRate();
#endif

    goto done;
#if !defined(PLATFORM_PC)
  fail:
    UNSET_SETTING_SAMPLE_RATE();
#endif

  done:
    return errNo;
  }

  void continueSetSampleRate() {
    uint32_t epochDur;
    uint16_t aggWinSize;
    uint16_t mvPerDay;
    computeRates(mLifetime, mVoltage, 0, 0, 1, 1, &epochDur, &aggWinSize, &mvPerDay);
    dbg(DBG_USR2, "computed epoch dur for query %d = %d\n", mCurSampleRateQuery, epochDur);
    setRate(mCurSampleRateQuery, (short)(epochDur & 0x00007FFF));
    UNSET_SETTING_SAMPLE_RATE();

#ifdef kLIFE_CMD
    if (mLifetimeCommandPending) {
      call SetLifetimeCommand.commandDone("life", NULL, SCHEMA_SUCCESS);
      mLifetimeCommandPending = FALSE;
    }
#endif
  }


  /** Clock fired event --<br>
   Works as follows:<br>
   1) Output tuples from previous epochs<br>
   2) Deterimine what queries fire in this epoch<br>
   3) Collect samples from those queries<br>
   4) Fill in the tuples in those queries<br>
   5) Apply operators to those tuples<br>
   <p>
   While this is happening, results may arrive from other sensors
   nodes representing results from the last epoch.  Those results need
   to be forwarded (if we're just selection), or stored (if we're aggregating)
   <p>
   Question:  What to do if next time event goes off before this one is
   complete?  Right now, this we'll simply ignore later events if this
   one hasn't finished processing
   <p>
   As of 10/5/2002, moved main body into a task.
*/
event result_t AbsoluteTimer.fired() {

    if (mIsRunning) {
#ifdef qSNOOZE
      //set up the service scheduler on our first time through here
      if (mAllQueriesSameRate && 
	  !IS_SNOOZING() &&
	  mQs != NULL) {
	result_t r;
	
	ParsedQueryPtr pq = &(**mQs).q;
	tos_time_t t = call Time.get();
	tos_service_schedule sched;
	short sleepClocks = (pq->clocksPerSample);
	// long sleepUs = (sleepClocks * mOldRate);

	//don't sleep if the clock rate is fast
	if (pq->clocksPerSample <= WAKING_CLOCKS) {
	  mStopped = FALSE;
	  goto dontSleep;
	}

	
	//sched.start_time = call TimeUtil.addUint32(t,sleepUs); //start will be called at the beginning of the epoch
	t.low32 += ((int32_t)pq->clocksPerSample * kMS_PER_CLOCK_EVENT) - (t.low32 % ((int32_t)pq->clocksPerSample* kMS_PER_CLOCK_EVENT));

	sched.start_time = t; //call TimeUtil.addUint32(t,1); //start now -- ??? changed to 1, added + 1
	sched.on_time = (((uint32_t)WAKING_CLOCKS + 1)* (uint32_t)mOldRate); //and stop will be called after WAKING_CLOCKS
	sched.off_time =(((uint32_t)sleepClocks - ((uint32_t)WAKING_CLOCKS + 1)) * (uint32_t)mOldRate);
	
	SET_SNOOZING();	
	r = call ServiceScheduler.reschedule(kTINYDB_SERVICE_ID, sched); //wait til this fires before we start...
	//synchronize with whoever sent us this query
	/* TS
	if (mCurSchedTime != 0) {
	  call TimeUtil.addint32(t, mCurSchedTime);
	  call ServiceScheduler.setNextEventTime(t);
	  mCurSchedTime = 0;
	}
	*/
      } else {
#endif
      dontSleep:

	if (!mStopped) {
	  
	  tos_time_t cur_time = call Time.get();
	  uint32_t rateUs = ((uint32_t)mOldRate); //convert to microsecs
	  
	  // call Leds.redToggle(); 
	  cur_time.low32 -= (cur_time.low32 % rateUs);
	  cur_time.low32 += rateUs; //schedule for this time in the future
	  atomic {
	    call AbsoluteTimer.set(cur_time);
	  }
	  decrementQueryCounter();
	  post mainTask();
	}
#ifdef qSNOOZE
      }
#endif
    }
    return SUCCESS;
  }

  task void mainTask() {
    //dbg(DBG_USR3,"IN CLOCK \n"); //fflush(stdout);

    //don't do anything if we're currently sending (shouldn't need this, but...)

    if (mStopped) { 
      call AbsoluteTimer.cancel();
      return;

    }

    if(IS_SENDING_MESSAGE())  {
      
      call NetworkMonitor.updateContention(TRUE, SEND_BUSY_FAILURE);
      mNumBlocked++;
      if (mNumBlocked > 32){
	mNumBlocked = 0;
	outputDone(&mMsg);
	//UNSET_SENDING_MESSAGE();
      } else {
	//call statusMessage("sending");
	return;
      }
    }
    
    mNumBlocked = 0;


    if (mDeliverWait) {
      mDeliverWait--;
      if (mDeliverWait == 0) {
	ParsedQuery *pq;
	bool pending = FALSE;
	TinyDBError err;
	
	if (TOS_LOCAL_ADDRESS == 0) dbg(DBG_USR1, "deliver wait is 0\n");
	if (isRoot() && mWaitIsDummy) {
#ifndef USE_LOW_POWER_LISTENING
	  if (mQs != NULL)
	    sendDummyQueryResult((**mQs).q.qid, (**mQs).q.numFields, (**mQs).q.currentEpoch);
#endif
	} else {
	  if (getQuery(mEnqResult.qid, &pq)) {
	    
	    err = call DBBuffer.enqueue(pq->bufferId, &mEnqResult, &pending, pq);
	    
	    //ignore result buffer busy items for now, since they just mean
	    //we can't keep up with the sample rate the user is requested , but we
	    //shouldn't abort
	    if (err != err_ResultBufferBusy && err !=  err_NoError)
	      TDB_SIG_ERR(err);
	  }
	  if (!pending) post deliverTuplesTask();
	}

      }else
	return;
    } else {

      if (mSendQueryNextClock) {
	mSendQueryNextClock = FALSE;
	mSendingQuery=TRUE;
	post sendQuery();
      }

    }

    //test to see if we're already sampling, in which case we better
    //not reinvoke sampling!
    if (IS_FETCHING_ATTRIBUTE() || IS_STARTING_ATTRIBUTE()) {
      //call statusMessage("fetching");
      mFetchTries++;
      //so we can escape a blocked fetch
      if (mFetchTries < UDF_WAIT_LOOP)
	return;
      else
	{
	  if (IS_FETCHING_ATTRIBUTE())
	    UNSET_FETCHING_ATTRIBUTE();
	  if (IS_STARTING_ATTRIBUTE())
	    UNSET_STARTING_ATTRIBUTE();
	}
    } else if (IS_ROUTING_TUPLES()) {
      //call statusMessage("routing");
      return;
    } else if ( IS_DELIVERING_TUPLES()) { 
      //call statusMessage("delivering");
      return;
    }  else if (IS_AGGREGATING_RESULT()) {
      //call statusMessage("aggregating");
      return;
    }

	if (IS_SENDING_QUERY()) {
		mSendQueryCnt++;
	}


    mFetchTries = 0;


    //  TOS_SIGNAL_EVENT(TUPLE_ROUTER_NEW_EPOCH)();
    mCurRouteQuery = NULL; //find the first query we need to deliver results for
    mCurExpr = -1;
    dbg(DBG_USR3,"POSTING TASK.");//fflush(stdout);



#ifdef qADAPTIVE_RATE
    {
      QueryListHandle qlh = mQs;
      
      while (qlh != NULL) {
	uint16_t contention = call NetworkMonitor.getContention();
	//reselect the sample rate if contention is high
	if (contention > HIGH_CONTENTION_THRESH) {
	  if ((**qlh).q.savedEpochDur < 1024) { //don't adapt to slower than once per second
	    (**qlh).q.savedEpochDur += (**qlh).q.savedEpochDur >> 4; //8% slowdown
	    setRate((**qlh).q.qid, (**qlh).q.savedEpochDur);
	  }
	} else if (contention < LOW_CONTENTION_THRESH) { //and crank it back up as contention goes low
	  if ((**qlh).q.savedEpochDur > (**qlh).q.epochDuration) {
	    (**qlh).q.savedEpochDur -= (**qlh).q.savedEpochDur >> 4; //8% speedup
	    if ((**qlh).q.savedEpochDur < (**qlh).q.epochDuration)
	      (**qlh).q.savedEpochDur = (**qlh).q.epochDuration;
	    setRate((**qlh).q.qid, (**qlh).q.savedEpochDur);
	  }
	}
	qlh = (QueryListHandle)(**qlh).next;
      }
    }
#endif


    post deliverTuplesTask();

  }

  /* --------------------------------- Tuple Output Routines ---------------------------------*/

  /** Walk through queries, finding ones that have gone off (timer reached 0), and
      where the tuples are complete.  Output said tuples to the appropriate
      output buffers.
      <p>
      mCurRouteQuery contains the last query routed, or NULL if starting at
      the first query (it's not a parameter, since this task needs to be rescheduled
      as successive tuples are delivered)
  */
  task void deliverTuplesTask() {
    bool success;
    bool didAgg = FALSE;
    bool pending = FALSE;
  
    // if (IS_SENDING_MESSAGE()) return; //wait til networking send is done...
    dbg(DBG_USR3,"IN DELIVER TUPLES TASK.\n");//fflush(stdout);
    SET_DELIVERING_TUPLES();
    
    if (mCurRouteQuery != NULL) {
      dbg(DBG_USR2, "end of epoch\n");
	if (!pending) resetTupleState(&(**mCurRouteQuery).q); //done with this tuple...
    }

    mCurRouteQuery = nextQueryToRoute(mCurRouteQuery);
    if (mCurRouteQuery != NULL) {

      ParsedQuery *pq = &(**mCurRouteQuery).q;
      Expr *e = nextExpr(pq);
      TinyDBError err = err_NoError;
      QueryResult qr;
      uint16_t size;

      //init success
#ifndef ROOT_SAMPLE
      success = (TOS_LOCAL_ADDRESS == pq->queryRoot)? FALSE : TRUE; //don't deliver tuples for root
#else
      success = TRUE;
#endif
      pq->needsData = FALSE;
      call QueryResultIntf.initQueryResult(&qr);
      // stamp current epoch number
      if (TOS_LOCAL_ADDRESS==0)
	  dbg(DBG_USR1, "stamping epoch number %d\n", pq->currentEpoch);
      qr.epoch = pq->currentEpoch;
      qr.qid = pq->qid;

      //scan the query, looking for an aggregate operator --
      //if we find it, output all the tuples it knows about --
      //otherwise, just output the tuple associated with the query
      while (e != NULL) {
	if (e->opType != kSEL) {
	  //add all of the aggregate results to the query result data structure

	  err = call addResults(&qr, pq, e);
	  didAgg = TRUE;
	  //break;
	} else {
	  if (!e->success) success = FALSE;
	}
	e = nextExpr(pq);
      }

      //then output the query result
      //call Leds.redToggle();
      if (didAgg && err == err_NoError && call QueryResultIntf.numRecords(&qr,pq) > 0) {
	//enqueue all the results from this aggregate

	mEnqResult = qr;
	mWaitIsDummy = FALSE;
	err = sendTuple(pq, &mEnqResult, &pending);

      }  else if (success && !didAgg) {       //just a selection query -- enqueue appropriate results


	mEnqResult = qr;

	call QueryResultIntf.fromTuple( &mEnqResult, pq , call ParsedQueryIntf.getTuplePtr(pq));

	
	mWaitIsDummy = FALSE;
	//	call Leds.redToggle();
	err = sendTuple(pq, &mEnqResult, &pending);

      }


      //one shot queries may have finished scanning their buffer
      if (pq->fromBuffer != kNO_QUERY && pq->epochDuration == kONE_SHOT)
	{
	  uint8_t fromBuf;
	  err = call DBBuffer.getBufferId(pq->fromBuffer, pq->fromCatalogBuffer, &fromBuf);
	  //stop queries that have scanned the entire buffer
	  err = call DBBuffer.size(fromBuf, &size);
	  if (err != err_NoError || pq->curResult++ >= size)
	    {
	      //if this is an event based query, stop the query running but
	      //don't delete it
	      if (pq->hasEvent)
		{
		  pq->running = FALSE;
		  pq->curResult = 0;
		}
	      else
		{
		//wait a little while before actually deleting queries so that
		//pending results can filter up the routing tree.
		  pq->markedForDeletion = EPOCHS_TIL_DELETION; //we need to destroy this query asap
		}
	    }
	}

      else if (pq->hasForClause && pq->numEpochs > 0 && pq->currentEpoch > pq->numEpochs)
	{
	  //wait a little while before actually deleting queries so that
	  //pending results can filter up the routing tree.
	  pq->markedForDeletion = EPOCHS_TIL_DELETION; //we need to destroy this query asap
	}
      //send tuples for next query
      if (!pending) post deliverTuplesTask();
      mCurExpr = -1; //reset for next query

    } else {
      UNSET_DELIVERING_TUPLES(); //now that tuples from last epoch are delivered, start fetching
                                //new tuples
      dbg(DBG_USR3,"FETCTHING TUPLES\n"); //fflush(stdout);

      startFetchingTuples();
    }
  }

  /** Event that's signalled when a send is complete */
  result_t outputDone(TOS_MsgPtr msg) {



    if (IS_SENDING_MESSAGE() ) {
      UNSET_SENDING_MESSAGE();
      //call Leds.redToggle();
      //call PowerMgmtEnable();
      // call Leds.greenToggle();
      if (/*msg == &mQmsg &&*/ IS_SENDING_QUERY()) {
	mSendQueryNextClock = TRUE;
      }

    }
    
    //if radio is supposed to be off, turn it off
    if (mRadioWaiting) {
      mRadioWaiting = FALSE;
    }

    if (mSendingResult) {
      mSendingResult = FALSE;
      if (!signal RadioQueue.enqueueDone()) 
	post deliverTuplesTask();

    }

    return SUCCESS;

  }


  //send a tuple -- either delaying it a little if the epoch is 
  //long enough or sending it directly
  TinyDBError sendTuple(ParsedQuery *pq, QueryResultPtr qr, bool *pending) {
    TinyDBError err = err_NoError;

    call queryResultHook(pq->bufferId, qr, pq);
    if (pq->clocksPerSample > kMIN_SLEEP_CLOCKS_PER_SAMPLE) {
      if (TOS_LOCAL_ADDRESS == 0)
	dbg(DBG_USR1, "enqueuing tuple \n");
      mDeliverWait = (call Random.rand() % kMAX_WAIT_CLOCKS) + 1; //number of kCLOCK_MS_PER_SAMPLE ms periods to wait
      *pending = TRUE;
    } else {
      err = call DBBuffer.enqueue(pq->bufferId, qr, pending, pq);
      
      //ignore result buffer busy items for now, since they just mean
      //we can't keep up with the sample rate the user is requested , but we
      //shouldn't abort
      if (err != err_ResultBufferBusy && err !=  err_NoError)
	TDB_SIG_ERR(err);
    }

    return err;
  }

  //after a clock fired event, walk through all the queries
  //and decrease the remaining time by one
  void decrementQueryCounter() {
    mClockCount ++;
    //mClockCount = 1; //ZZZ
    //if (++crap == 16) {
    //  call Leds.yellowToggle();
    //  crap = 0;
    //}
  }

  event result_t Network.sendDataDone(TOS_MsgPtr msg, result_t success)
    {
      return outputDone(msg);
    }

  event result_t Network.sendQueryRequestDone(TOS_MsgPtr msg, result_t success)
    {
      return outputDone(msg);
    }
  
  event result_t Network.sendQueryDone(TOS_MsgPtr msg, result_t success)
    {
      return outputDone(msg);
    }
  
  void sendDummyQueryResult(uint8_t qid, uint8_t numFields, uint16_t curEpoch) {
    if (!IS_SENDING_MESSAGE()) {
      QueryResultPtr newQrMsg;

      SET_SENDING_MESSAGE();
      call Leds.redToggle();
      newQrMsg = call Network.getDataPayLoad(&mMsg);
      newQrMsg->qid = qid;
      newQrMsg->result_idx = 0;
      newQrMsg->epoch = curEpoch;
      newQrMsg->qrType = kNOT_AGG;
      newQrMsg->d.t.notNull = 0;
      newQrMsg->d.t.numFields = numFields;
      newQrMsg->d.t.qid = qid;
      atomic {
	mTimestampMsg = &mMsg;
	mMustTimestamp = TS_QUERY_RESULT_MESSAGE;
      }
      if (call Network.sendDataMessageTo(&mMsg,TOS_BCAST_ADDR) != err_NoError) {
	atomic {
	  mMustTimestamp = TS_NO;
	}
	outputDone(&mMsg);
      } 
    }
  }

  void startFetchingTuples() {
    QueryListHandle qlh = mQs;
    bool mustSample = FALSE;
    bool didReset = FALSE;
    bool needsNoData = TRUE;
	ParsedQueryPtr firstQ = NULL;
    //update queries, determine if any needs to sample data this epoch
    while (qlh != NULL) {
      //reset queries that just restarted
      if ((**qlh).q.clocksPerSample > 0 && !(**qlh).q.needsData &&
#ifdef qSNOOZE
	  (((**qlh).q.clockCount == WAKING_CLOCKS) ||
#endif
	  (**qlh).q.clockCount == (int16_t)((**qlh).q.clocksPerSample)
#ifdef qSNOOZE
	   )
#endif
	  )
	{


	  didReset = TRUE;

	  if (!isRoot() || (**qlh).q.hasAgg) {
	    (**qlh).q.needsData = TRUE;
	  }
	  //else (**qlh).q.clockCount = 0;
	}

      if ((**qlh).q.hasAgg) {
	needsNoData = FALSE;
      }

      if ((**qlh).q.running && (**qlh).q.clocksPerSample > 0) {
	
	if (didReset) {
	  didReset = FALSE;
	  mLastHeard ++;  //increment count since we last heard something
	  call Leds.yellowToggle();
	  //call Leds.redToggle();
	  //call UartDebugger.writeLine("epoch");
#ifdef HAS_ROUTECONTROL
	  // force a route update every epoch if we are not sleeping
	  // if ((**qlh).q.clocksPerSample <= WAKING_CLOCKS)
		  // call RouteControl.manualUpdate();
#endif
	  if ((**qlh).q.markedForDeletion > 0) {
	    if (--(**qlh).q.markedForDeletion == 0) { //delete the query
	      //force removal, since we know it's OK...
		  mQidToRemove = (**qlh).q.qid;
		  mForceRemove = TRUE;
		  post removeQueryTask();
	    } else {
	      (**qlh).q.clockCount += (**qlh).q.clocksPerSample; // just reschedule this query...
	    }
	  } else {
	    //only actually process local tuples if we're not the root.
#ifndef ROOT_SAMPLE
	    if ((**qlh).q.queryRoot != TOS_LOCAL_ADDRESS)
#endif
		{
	      mustSample = TRUE;
		  if (firstQ == NULL)
            firstQ = &(**qlh).q;
		}

	    (**qlh).q.currentEpoch++;
	  }
	}

	(**qlh).q.clockCount -= mClockCount;	  
#ifdef qSNOOZE
	if (!mAllQueriesSameRate || (**qlh).q.clocksPerSample <= WAKING_CLOCKS) {
#endif
	  if ((**qlh).q.clockCount <= 0) {
	    (**qlh).q.clockCount = (**qlh).q.clocksPerSample;
	  }
#ifdef qSNOOZE
	}
#endif
	//break;
      }
      qlh = (QueryListHandle)(**qlh).next;
    }
    mClockCount = 0;

    if (mQs) {
      qlh = mQs;
      if (isRoot() && needsNoData && (**qlh).q.clocksPerSample > kMIN_SLEEP_CLOCKS_PER_SAMPLE) {
	mWaitIsDummy = TRUE;
	dbg(DBG_USR1,"DUMMY WAIT\n");
	//call Leds.redToggle();
#ifdef qSNOOZE
	if ((**qlh).q.clocksPerSample >= WAKING_CLOCKS)
	  mDeliverWait = WAKING_CLOCKS / 2; //half way through waking period...
	else
#endif
	  mDeliverWait = (**qlh).q.clocksPerSample/2;
      }
    }


    if (mustSample) {
	  // ParsedQueryPtr q;
      // (void)getNextQueryField(&q);
	  if (firstQ != NULL) {
         mNumAttrs = firstQ->numFields;
         SET_STARTING_ATTRIBUTE();
         startQueryAttrs(firstQ);
      }
      // fetchNextAttr();
    }
  

  }

  void resetTupleState(ParsedQuery *q) {
    short i;
    Expr *e;
#ifdef HSN_ROUTING
	bool gotAgg = FALSE;
#endif

    //clear out this tuple
    call TupleIntf.tupleInit(q,call ParsedQueryIntf.getTuplePtr(q));
    for (i = 0; i < q->numExprs; i++) {
      e = call ParsedQueryIntf.getExprPtr(q, i);
      call AggOperator.endOfEpoch(q, e);
#ifdef HSN_ROUTING
	  if (e->opType != kSEL)
	  	gotAgg = TRUE;
#endif
    }
#ifdef HSN_ROUTING
	if (gotAgg)
	{
		mHSNValue = mHSNValue - (mHSNValue >> 1) + (mNumMerges >> 1);
		mNumMerges = 0;
	}
#endif
  }

  /* --------------------------------- Tuple Building Routines ---------------------------------*/

  /** Fetch the next needed attribute, and
      @return TRUE if an attribute was found and (possibly)
      more attributes exist.

      Does this by scanning the current queries, finding those
      that have fired and need fields filled in, and filling in those
      fields.

      Uses mLastQuery to track the last query that results were fetched
      for, and mFetchingField to track the last field that was filled in.
      
      Note that a return value of TRUE doesn't
      mean the recent attribute was actually found
  */
  bool fetchNextAttr() {
    AttrDescPtr queryField;
    TupleFieldDesc fieldDesc;
    SchemaErrorNo errorNo;
    ParsedQuery *q;
    short i, fieldId = -1;
    bool pending;
    TinyDBError tdberr;
    uint8_t bufId;

    dbg(DBG_USR3,"in fetchNextAttr\n"); //fflush(stdout);

    //at least one query needs samples -- but which ones?
    fieldDesc = getNextQueryField(&q);
    if (fieldDesc.isNull == FALSE) {

      //get the result that we'll disassemble if this query fetches its
      //result from a buffer
      if (q->fromBuffer != kNO_QUERY) {
	mCurTupleIdx = fieldDesc.u.tupleIdx;
	//call UartDebugger.writeLine("noquery", 7);
	if (mLastQuery == NULL || mLastQuery != q) { //did we already read a result row?	  
	  mLastQuery = q; //no!

	  //call UartDebugger.writeLine("nolastquery", 11);
	  tdberr = call DBBuffer.getBufferId(q->fromBuffer, q->fromCatalogBuffer, &bufId);
	  if (tdberr != err_NoError) {
	    TDB_SIG_ERR(tdberr);
	    return FALSE;
	  }
	  if (q->epochDuration == kONE_SHOT) {
	    tdberr = call DBBuffer.getResult(bufId, q->curResult, &mResult, &pending); 
	  } else {
	    //call UartDebugger.writeLine("peek",4);
	    tdberr = call DBBuffer.peek(bufId, &mResult, &pending);
	  }
	  if (tdberr == err_ResultBufferBusy) {
	    TDB_SIG_ERR(tdberr);
	    return TRUE; //try again?
	  }
	  if (tdberr != err_NoError) {
	    TDB_SIG_ERR(tdberr);
	    return FALSE;
	  }

	  if (!pending) post fillInTask();

	} else { //yes, so copy the next result
	  post fillInTask();
	}
	return TRUE;
      } else if (q->fromBuffer == kNO_QUERY) {

	queryField = fieldDesc.u.attr;
	  mFetchingFieldId = queryField->idx;
	  //figure out this field's local query index


	//CAREFUL:  Invoke command can return very quickly, such that
	//we best have set this value before we call it, since if we do it
	//afterwards, it may completion before we have a chance to set the flag
	//So, we have to make sure to unset the flag below, when needed.
	SET_FETCHING_ATTRIBUTE();

	mLastQuery  = q;

	for (i = 0; i < q->numFields;i++) {
	    if (q->queryToSchemaFieldMap[i] == queryField->idx)
		fieldId = i;
	}
	if (fieldId != -1) {
	    // use pre-allocated tuple space
	    mResultBuf = call TupleIntf.getFieldPtr(q, call ParsedQueryIntf.getTuplePtr(q), fieldId);
	    if (call AttrUse.getAttrValue(queryField->name, mResultBuf, 
					  &errorNo) == SUCCESS) {
	      if (errorNo != SCHEMA_RESULT_PENDING) {

		post fillInTask();
	      }
	      if (errorNo != SCHEMA_ERROR)
		return TRUE;
	    }
	}

      }
    } else {
      
      //call UartDebugger.writeLine("wasnull", 7);
    }
    mLastQuery = NULL;
    return FALSE;
  }

  /** Scan queries, looking for fields that haven't been defined yet */
  TupleFieldDesc getNextQueryField(ParsedQuery **pq) {
    QueryListHandle qlh = mQs;
    AttrDescPtr attr = NULL;
    TupleFieldDesc d;
    TinyDBError err;
    uint8_t idx;

    d.isNull = TRUE;

    while (qlh != NULL) {
      if ((**qlh).q.clocksPerSample > 0 &&  (**qlh).q.needsData) { //is this query's time up?
	Tuple *t = call ParsedQueryIntf.getTuplePtr(&(**qlh).q);
	ParsedQuery *q = &(**qlh).q;
	dbg(DBG_USR3,"q->qid = %d, t->qid = %d, t->numFields = %d\n", q->qid, t->qid, t->numFields);
	dbg(DBG_USR3,"calling GET_NEXT_QUERY_FIELD\n"); //fflush(stdout); 
	
	if (q->fromBuffer == kNO_QUERY) {
	    attr = call TupleIntf.getNextQueryField(q,t);
	    if (attr != NULL) {
		d.isAttr = TRUE;
		d.u.attr = attr;
		d.isNull = FALSE;
		break;
	    } 
	} else {

	  err = call TupleIntf.getNextEmptyFieldIdx(q,t, &idx);
	  if (err == err_NoError) {
	    d.isAttr = FALSE;
	    d.u.tupleIdx = idx;
	    d.isNull = FALSE;
	    break;
	  }
	}
      }
      qlh = (QueryListHandle)(**qlh).next;
    }
    if (qlh == NULL)
      *pq = NULL;
    else
      *pq = &(**qlh).q;

    return d;
  }

  /** Continue filling in tuple attributes and (if done with that)
      routing completed tuples to operators
  */
  void keepRouting() {
      if (! fetchNextAttr()) {
	UNSET_FETCHING_ATTRIBUTE(); //clear, and try again
	// XXX HACK should only turn off attributes in the current query
	call AttrControl.stop();
	SET_ROUTING_TUPLES();
	//no more attributes to fetch, start processing tuples....
	mCurRouteQuery = nextQueryToRoute(NULL);
	mCurExpr = -1;
	
	post routeTask();
      }
  }

  /** If this is not a read from a buffer, 
      Set the value of field mFetchingFieldId (which is the id of an attribute
      in the schema) in all queries that need the field to the data contained
      in mResultBuf
    
      If this is from a buffer, copy the field in mCurTupleIdx of mResult
      into the current tuple

      @param errorNo An error (if any) returned by the schema in response to the getAttr command
  */
  void fillInAttrVal( SchemaErrorNo errorNo)
    {
      ParsedQuery *pq = mLastQuery;
      char *resultBuf ;
      TinyDBError err;
	
	if (pq == NULL) return;

      if (pq->fromBuffer == kNO_QUERY) {
	short id = mFetchingFieldId; //the mote-specific field this command has data for
	short i;
	QueryListHandle qlh = mQs;

	resultBuf = mResultBuf;

	//dbg(DBG_USR3,"GOT DATA, COMMAND data = %d, errorNo = %d\n", *(short *)resultBuf, errorNo);

	while (qlh != NULL) {
	  ParsedQuery *q = &(**qlh).q;
	  if (q->clocksPerSample > 0 && q->needsData &&
	      q->fromBuffer == kNO_QUERY) { //this query needs ADC data
	    Tuple *t = call ParsedQueryIntf.getTuplePtr(q);
	    for (i = 0; i < q->numFields; i++) {
	      if (q->queryToSchemaFieldMap[i] == id) { //the correct field in this query
		call TupleIntf.setField(q, t, i, resultBuf);

		//dbg(DBG_USR3,"SET QUERY FIELD : %d\n", i);
	      }
	    }
	  }
	  qlh = (QueryListHandle)(**qlh).next;
	}

      } else {
	Tuple *t = call ParsedQueryIntf.getTuplePtr(pq);
	uint8_t bufId;

	resultBuf = call TupleIntf.getFieldPtr(pq,t, mCurTupleIdx);

	if (resultBuf == NULL) {
	  //call UartDebugger.writeLine("NULL", 4);
	  // keepRouting();
	   return;
	}
	err = call DBBuffer.getBufferId(pq->fromBuffer, pq->fromCatalogBuffer, &bufId);
	if (err != err_NoError) {
	  TDB_SIG_ERR(err);
	  return;
	}

	err = call DBBuffer.getField(bufId,
				     &mResult, 
				     pq->queryToSchemaFieldMap[mCurTupleIdx], 
				     resultBuf);
	if (err != err_NoError) {
	  TDB_SIG_ERR(err);
	  return;
	}

	//already wrote the data there, but need to twiddle bits
	call TupleIntf.setField(pq, t, mCurTupleIdx, resultBuf); 

      }
      keepRouting();
    }

  /** Used to make attribute setting split phase even when its not ... */
  task void fillInTask() {
    fillInAttrVal(SCHEMA_RESULT_READY);
  }

  /** Completion event after some data was fetched
      Params should be filled out with the result of the command
      @param name The name of the attribute that was fetched
      @param resultBuf The value of the attribute
      @param errorNo Errors that occurred while fetching the result
  */
  event result_t AttrUse.getAttrDone(char *name, char *resultBuf, SchemaErrorNo errorNo)
    {
      if (resultBuf == (char *)&mVoltage)
	continueSetSampleRate();
      else 
	fillInAttrVal( errorNo);
      return SUCCESS;
    }

  /* --------------------------------- Tuple Routing Routines ---------------------------------*/


  /** routeTask does the heavy lifting of routing tuples to queries.
      It assumes the tuples stored in each query that needs to be routed
      during this epoch have been initialized.  It then iterates through the
      operators in each query, routing tuples to them in succession.
   
      Tuples are routed through a query at a time, and always in a fixed order.
      mCurRouteQuery is set to the query for which tuples are currently being routed.
  */
  task void routeTask() {
    if (mCurRouteQuery != NULL) {
      ParsedQuery *q = &(**mCurRouteQuery).q;
      if (!routeToQuery(q,  mCurTuple)) {
	//false here means move on to the next query
	mCurRouteQuery = nextQueryToRoute(mCurRouteQuery);
	post routeTask();
      }
    } else {

      UNSET_ROUTING_TUPLES(); //all done routing
    }
  }

  /** @return the next query in the query list that needs to be output<br>
      Aassumes that all attributes have already been filled out (e.g. fetchNextAttr() returned false)

      mCurTuple is changed to point at the tuple corresponding to the returned query.
  */
  QueryListHandle nextQueryToRoute(QueryListHandle curQuery) {
    mCurTuple = NULL;
    if (curQuery == NULL) {
      curQuery = mQs;
    } else
      curQuery = (QueryListHandle)(**curQuery).next;

    while (curQuery != NULL) {
      if ((**curQuery).q.clocksPerSample > 0 && (**curQuery).q.needsData) { //this query is ready to go
	mCurTuple = call ParsedQueryIntf.getTuplePtr(&(**curQuery).q);

	break;
      } else {
	curQuery = (QueryListHandle)(**curQuery).next;
      }
    }

    return curQuery;
  }

  /** Route the specified tuple to the first operator of the
      specified query.  This will send the tuple to an operator,
      which will return the tuple when it is done.
      @param q The query that t should be routed to
      @param t The tuple to route
      @return TRUE if the tuple was routed, FALSE otherwise
  */
  bool routeToQuery(ParsedQuery *q, Tuple *t) {
    Expr *e = nextExpr(q);

    if (e != NULL) {   //assume expressions are listed in the order
      e->success = TRUE; //they should be executed! (e.g. selections before aggs)
      if (e->opType != kSEL) {
	call AggOperator.processTuple(q,t,e);
      } else {
	call SelOperator.processTuple(q,t,e);
      }
      return TRUE; //more routing to be done
    } else {
      return FALSE; //routing all done
    }
  }


  /** Uses mCurExpr to track the current expression
      in q that is being applied.
      <br>
      mCurExpr should be set to -1 to get the first expression
      in q.
      <br>
      The expression id is not an explicit parameter since expression
      routing needs to be resumed after the previous split phase
      expression application.
      <br>
      @return the next expression in q, or null if no such expression
      exists.
  */
  Expr *nextExpr(ParsedQuery *q) {
    if (++mCurExpr >= q->numExprs) {
      mCurExpr = -1;
      return NULL;
    } else {
      Expr *e;
      e =  (call ParsedQueryIntf.getExprPtr(q,mCurExpr));
      return e;
    }
    
  }

  /* --------------------------------- Query Utility Routines ---------------------------------*/
  /** @return TRUE if the query exists.
      @param qid The query to fetch
      @param q Will point to the query pointer upon return if the return
      value is TRUE.
  */
  bool getQuery(uint8_t qid, ParsedQuery **q) {
    QueryListHandle curq;

    curq = mQs;
    while (curq != NULL) {
      if ((**curq).q.qid == qid) {
	*q = &(**curq).q;
	return TRUE;
      } else
	curq = (QueryListHandle)(**curq).next;
    }
    *q = NULL;
    return FALSE;
  }

  command ParsedQueryPtr QueryProcessor.getQueryCmd(uint8_t qid) {
    ParsedQueryPtr pq;
    if (getQuery(qid,&pq))
      return pq;
    else
      return NULL;
  }

  command short QueryProcessor.numQueries() {
    QueryListHandle curq;
    short count = 0;

    curq = mQs;
    while (curq != NULL) {
      count++;
      curq = (QueryListHandle)(**curq).next;
    }
    return count;
  }


  command ParsedQueryPtr QueryProcessor.getQueryIdx(short i) {
    QueryListHandle curq;

    curq = mQs;
    while (curq != NULL) {
      if (i-- == 0) return &(**curq).q;
      curq = (QueryListHandle)(**curq).next;
    }
    return NULL;
  }

  /** Given a processor message return the owner (origninating node) of the query, or
      -1 if the query is unknown or the message is a query processor message.

      @param msg The query for which the root is sought
  */
  command short QueryProcessor.msgToQueryRoot(TOS_MsgPtr msg) {
    uint8_t msgType = msg->type;
    uint8_t qid;
    short root;
    ParsedQueryPtr pq;
    

    if (msgType != kDATA_MESSAGE_ID && msgType != kQUERY_MESSAGE_ID && msgType != kQUERY_REQUEST_MESSAGE_ID)
      return -1;

    //hack :  assume first byte after header is query id!
    qid = call QueryResultIntf.queryIdFromMsg(call Network.getDataPayLoad(msg));

    pq = call QueryProcessor.getQueryCmd(qid);

    if (pq == NULL) {
      root =  -1;
    }
    else {
      root =pq->queryRoot;
    }
    return root;
  }


  command bool QueryProcessor.queryProcessorWantsData(QueryResultPtr qr) {
    uint8_t qid = qr->qid;
    ParsedQuery *pq = call QueryProcessor.getQueryCmd(qid);

    if (pq == NULL) {
      return FALSE;
    } else {
      return pq->hasAgg;
    }
    return FALSE;
  }

  /** Given a query, parse it into pq
      @param q The query to convert
      @param pq The parsed query to fill in.  Assumes that
      pq has been allocated with ParsedQueryIntf.pqSize(q) bytes.
      @return TRUE if successful
  */
  bool parseQuery(Query *q, ParsedQuery *pq) {

    TinyDBError err;
    bool pending = FALSE;

    dbg(DBG_USR3, "## TupleRouterM.parseQuery called\n");
    
    
    pq->qid = q->qid;
    pq->numFields = q->numFields;
    pq->numExprs = q->numExprs;
    pq->epochDuration = q->epochDuration;
    pq->savedEpochDur = q->epochDuration;
	pq->numEpochs = q->numEpochs;
    pq->fromBuffer = q->fromBuffer;
    pq->bufferType = q->bufferType;
    pq->bufferId = q->bufferId;
    pq->markedForDeletion = 0;
    pq->currentEpoch = 0;
    pq->buf = q->buf;
    pq->queryRoot = q->queryRoot;
    pq->hasEvent = q->hasEvent;
    pq->tableInfo = NULL;
    pq->hasAgg = FALSE;

    pq->fromCatalogBuffer = q->fromCatalogBuffer;

    mCurQueryPtr  = q;
    mTempPQ = pq;

    if (q->hasEvent) {
#ifdef kSUPPORTS_EVENTS
      char queryIdStr[5];
      ParamList params;
      EventDesc *evt;

      queryIdStr[0] = 0;
  #if defined(PLATFORM_PC) //itoa not on pc
      sprintf(queryIdStr,"%d", q->qid);
  #else
      itoa(q->qid, queryIdStr, 10);
  #endif
      params.numParams = 0;

      dbg(DBG_USR2, "registering command %s for event %s\n",  queryIdStr, q->eventName);

      //make sure this is a known event
      evt = call EventUse.getEvent(q->eventName);
      if (evt == NULL) return FALSE;

      //now, register ourselves as the command handler for this event
      if (call EventFiredCommand.registerCommand(queryIdStr,VOID, 0, &params) == FAIL)
	return FALSE;
      
      pq->eventId = evt->idx;
      pq->eventCmdId = (call CommandUse.getCommand(queryIdStr))->idx;
      //request that our command be called whenever this event fires.
      if (call EventUse.registerEventCallback(q->eventName, queryIdStr) == FAIL) {
	return FALSE;
      }
      dbg(DBG_USR2, "registration successuful.\n");
      //this query is started by an event... 
#endif
      pq->running= FALSE;
    } else {
      //if query isn't triggered by an event, it's running
      if ((pq->bufferType == kRAM || pq->bufferType == kEEPROM) &&
	  pq->buf.ram.create == 1)
	pq->running = FALSE;
      else
	pq->running = TRUE;
    }

    //initial fromBuffer here if we have a named input buffer
    if (pq->bufferType == kRAM || pq->bufferType == kEEPROM) {
      RamBufInfo *ram = &pq->buf.ram;
    
      
      if (ram->hasInput) {
	uint8_t bufId;

	err = call DBBuffer.getBufferIdFromName(ram->inBufName,&bufId);
	if (err != err_NoError) {
	  //if it doesn't exist, look for it in the header
	  UNSET_OPENING_WRITE_BUF(); 
	  
	  if (pq->bufferType == kEEPROM) {
#ifdef kMATCHBOX
	    err = call DBBuffer.loadEEPROMBuffer(ram->inBufName);
#else
	    err = err_NoMatchbox;
#endif
	  }
	  if (err !=  err_NoError) {
	    TDB_SIG_ERR(err);
	    return FALSE;
	  }  else
	    pending = TRUE;
	}


	if (!pending) {
	  err = call DBBuffer.qidFromBufferId(bufId, &pq->fromBuffer);
	  if (err != err_NoError) {
	    TDB_SIG_ERR(err);
	    return FALSE;
	  }
	}
      }
    }

    if (!pending) continueFromBufferFetch(err_NoError);

    return TRUE;
  }

  //Called on return from loadEEPromBuffer or from parseQuery 
  void continueFromBufferFetch(TinyDBError err) {
    ParsedQuery *pq = mTempPQ;

    uint8_t bufferId;
    uint8_t i;

    if (err != err_NoError) {
      //      TDB_SIG_ERR(err);
      parsedQuery(FALSE);
      return;
    }

    if ((pq->bufferType == kRAM || pq->bufferType == kEEPROM) && pq->buf.ram.hasInput) {
      RamBufInfo *ram = &pq->buf.ram;
      err = call DBBuffer.getBufferIdFromName(ram->inBufName,&bufferId);
      if (err != err_NoError) {
	TDB_SIG_ERR(err);
	parsedQuery(FALSE);
	return;
      }

      err = call DBBuffer.qidFromBufferId(bufferId, &pq->fromBuffer);
      if (err != err_NoError) {
	TDB_SIG_ERR(err);
	parsedQuery(FALSE);
	return;
      }
    }


    mCurField = 0;

    if ((uint8_t)pq->fromBuffer != kNO_QUERY) {
      err = call DBBuffer.getBufferId(pq->fromBuffer, pq->fromCatalogBuffer, &bufferId);
      if (err != err_NoError) {
	TDB_SIG_ERR(err);
	parsedQuery(FALSE);
	return;
      }
      
      //call UartDebugger.writeLine("getting map", 11);

      for (i = 0; i < pq->numFields; i++) {
	Field f = call QueryIntf.getField(mCurQueryPtr,i);
	err = call DBBuffer.getFieldId(bufferId, &f, &pq->queryToSchemaFieldMap[i]);
	if (err != err_NoError)
	  TDB_SIG_ERR(err);
      }


    }


    continueParsing(SUCCESS); //continue, split phased possibly
  }

  /** Finish parsing, to allow split phase operations
      which allocate named query fields to complete
      Must be called initially from parsedQuery.
  */
  void continueParsing(result_t success) {
    int i;
    ParsedQuery *pq = mTempPQ;
    Query *q = mCurQueryPtr;
    AttrDesc *attr;
    
    if (!success) parsedQuery(FALSE);

    if (pq->fromBuffer == kNO_QUERY) { //did fromBuffer above.
      while (mCurField < q->numFields) {
	Field *f = call QueryIntf.getFieldPtr(q,mCurField);
	//dbg(DBG_USR3,"Setting field %d (%s)\n", mCurField, f->name);//fflush(stdout);
	
	if ((pq->bufferType == kRAM  || pq->bufferType == kEEPROM) && pq->buf.ram.create == 1) {
	  //add the field -- split phase op
	  pq->queryToSchemaFieldMap[mCurField] = TYPED_FIELD;
	  call Table.addNamedField(pq, mCurField++, f->name, f->type);
	  return;
	} else {
	  attr = call AttrUse.getAttr(f->name);
	  if (attr != NULL) {
	    pq->queryToSchemaFieldMap[mCurField] = attr->idx;
	  } else {
	    pq->queryToSchemaFieldMap[mCurField] = NULL_QUERY_FIELD;
	  }
	  mCurField++;
	}
      }
    }

    for (i = 0; i < q->numExprs; i++) {
      Expr e = call QueryIntf.getExpr(q,i);
      
      e.idx = i;
      //dbg(DBG_USR3," e.opType = %d, e.opVal.field = %d, e.opVal.value = %d\n",
      //	      e.opType, e.ex.opval.field, e.ex.opval.value); //fflush(stdout);
      call ParsedQueryIntf.setExpr(pq, i, e);
      e = call ParsedQueryIntf.getExpr(pq,i);
      //dbg(DBG_USR3," e.opType = %d, e.opVal.field = %d, e.opVal.value = %d\n",
      //e.opType, e.ex.opval.field, e.ex.opval.value); //fflush(stdout);
      if (e.opType != kSEL)
	pq->hasAgg = TRUE;
    }




    parsedQuery(TRUE);
  }


  /** Allocates space for a query, given a query with numExprs and numFields filled in
      @param q The query to allocate a query data structure for
      @param callback The callback to fire when the allocation is complete
      @return TRUE if the allocation was successfully initiated (e.g. a callback is expected)
  */
  bool allocPendingQuery(MemoryCallback callback, Query *q) {
    mAllocState = STATE_ALLOC_IN_FLIGHT_QUERY;
    mAllocCallback = callback;
    return call MemAlloc.allocate(&mTmpHandle, call QueryIntf.size(q));
  }

  /** Allocate space for a parsed query
      After request compltes, add the result to qs linked list, and then
      call callback.

      @param callback Callback fired once allocation is complete
      @param q The query to use to initialize the parsed query
      @return true if request succesfully made (e.g. a callback is expected)
  */
  bool allocQuery(MemoryCallback callback, Query *q) {
    short size = (sizeof(QueryListEl) - sizeof(ParsedQuery)) + call ParsedQueryIntf.baseSize(q);

    mAllocState = STATE_ALLOC_PARSED_QUERY;
    mAllocCallback = callback;
    
    return call MemAlloc.allocate((Handle *)&mTmpHandle, size);
  
  }

  /** Resize qlh to have space for tuple at the end */
  bool reallocQueryForTuple(MemoryCallback callback, QueryListHandle qlh) {
    ParsedQuery *q = &(**qlh).q;
    short size = call MemAlloc.size((Handle)(qlh)) + call TupleIntf.tupleSize(q);
	

    //dbg(DBG_USR3,"resizing query for tuple to :  %d \n", size);//fflush(stdout);
    mAllocState = STATE_RESIZE_QUERY;
    mAllocCallback = callback;
    //dbg(DBG_USR3,"set alloc state to %d\n", mAllocState);
    return call MemAlloc.reallocate((Handle)qlh, size);

  }

  /** Return TRUE if we've heard about all the fields for the specified query */
  bool queryComplete(Query q) {
    //dbg(DBG_USR3,"completeMask = %x, %x\n",q.knownFields, q.knownExprs);//fflush(stdout);

    
    if (q.bufferType != kRADIO && !q.hasBuf) return FALSE;
    if (!q.hasEvent && q.needsEvent) return FALSE;
    if (q.hasForClause && q.numEpochs == 0) return FALSE;
    return (call QueryIntf.fieldsComplete(q) && call QueryIntf.exprsComplete(q));
  }


  void doTimeSync(uint8_t timeSyncData[5], uint16_t clockCount) {
    tos_time_t mytime;
#ifndef USE_LOW_POWER_LISTENING
    
    
    mytime.high32 = (timeSyncData[0] & 0x000000FF);
    mytime.low32 = *(uint32_t *)(&timeSyncData[1]);
    call TimeSet.set(mytime);
    
    checkTime();
#endif

  }
 
  void checkTime() {
    if (
#ifdef qSNOOZE
	mAllQueriesSameRate && 
#endif
	IS_SNOOZING() &&
	mQs != NULL) {
      
      
      tos_time_t epoch_end, mytime = call Time.get();
      int32_t diff,st,soe;
      ParsedQuery *pq = &((**mQs).q);
      int32_t epochMs = (int32_t)pq->clocksPerSample * kMS_PER_CLOCK_EVENT;

      //ourt = call ServiceScheduler.getNextEventTime(kTINYDB_SERVICE_ID);
      
      //ourt is the time we are going to sleep at
      //  when should we actually sleep at:
      //    WAKING_CLOCKS from the start of the epoch
      //    start of epoch (soe) = t.low32 - (t.low32 % (pq->clocksPerSample * kMS_PER_CLOCK_EVENT));
      //    sleep time (st) = soe + (WAKING_CLOCKS * kMS_PER_CLOCK_EVENT)
      //    but we don't want to change the actual waking time -- instead, adjust the sleep period
      //     by the diff between st and ourt
      //    if st is later than ourt, we want to sleep more time, so we wake up later next epoch
      //     so offset by (st - ourt)

      epoch_end = call ServiceScheduler.getNextEventTime(kTINYDB_SERVICE_ID);
      soe = mytime.low32 - (mytime.low32 % (epochMs));
#ifdef qSNOOZE
      st = soe + (WAKING_CLOCKS * kMS_PER_CLOCK_EVENT);
#else
      st = soe + epochMs;
#endif
      diff = st - (int32_t)epoch_end.low32;
      if (abs(diff) > 32) {
	
	if (abs(diff) > (epochMs >> 1)) { //should we adjust in the other direction?
	  diff = diff < 0 ? (diff + epochMs) : (diff - epochMs);
	}
	call ServiceScheduler.setExtraSleepTime(kTINYDB_SERVICE_ID, diff);
	if (diff != 0) mLastDiff = (int16_t)diff;
      }
    }
  }
  
  /* --------------------------------- Memory Callbacks ---------------------------------*/

  event result_t MemAlloc.allocComplete(Handle *handle, result_t complete) {

    dbg(DBG_USR3,"in alloc complete\n");//fflush(stdout);
    if (mAllocState == STATE_NOT_ALLOCING) return SUCCESS; //not our allocation

    switch (mAllocState) {
    case STATE_ALLOC_PARSED_QUERY:
      mAllocState = STATE_NOT_ALLOCING; //not allocating any more
      if (complete) {

	QueryListHandle qlh = (QueryListHandle)*handle;
	dbg(DBG_USR3,"alloced parsed query \n");//fflush(stdout);
	(**qlh).next = NULL;
	(**qlh).q.clocksPerSample = 0; //make sure this query wont be fired yet
	(**qlh).q.needsData = FALSE;
	//modifying this data structure is dangerous -- make sure timer thread doesnt run...

	atomic {
	  if (mTail == NULL) {
	    mTail = qlh;
	    mQs = qlh;
	  } else {
	    (**mTail).next = (void **)qlh;
	    mTail = qlh;
	  }
	}

#ifdef HSN_ROUTING
	signal HSNValue.adjuvantValueReset();
#endif
	mAllocCallback((Handle *)&mTail); //allow the application to continue
      } else
	TDB_SIG_ERR(err_OutOfMemory);
      break;
    case STATE_ALLOC_IN_FLIGHT_QUERY:
      mAllocState = STATE_NOT_ALLOCING; //not allocating any more
      if (complete) {

	dbg(DBG_USR3,"Alloced query.\n"); //fflush(stdout);

	(*mAllocCallback)(handle);
      } else {
	TDB_SIG_ERR(err_OutOfMemory);
	UNSET_READING_QUERY();
      }
      break;
    default:
      TDB_SIG_ERR(err_UnknownAllocationState);
      break;
    }
    return SUCCESS;
  }

  event result_t MemAlloc.reallocComplete(Handle handle, result_t complete) {
    //    dbg(DBG_USR3,"in realloc complete, state = %d, resize = %d, not_alloc = %d\n",
    //mAllocState, STATE_RESIZE_QUERY, STATE_NOT_ALLOCING); //fflush(stdout);
    if (mAllocState == STATE_NOT_ALLOCING) return SUCCESS; //not our allocation
    if (mAllocState == STATE_RESIZE_QUERY) {
      mAllocState = STATE_NOT_ALLOCING; //not allocating any more
     
      //dbg(DBG_USR3,"numFields = %d, free = %d\n",
      //(**(QueryListHandle)handle).q.numFields,
      //call MemAlloc.freeBytes());

      mTmpHandle = handle;
      if (complete)
	(*mAllocCallback)(&mTmpHandle);
      else
	TDB_SIG_ERR(err_OutOfMemory);
    }
    else
      TDB_SIG_ERR(err_UnknownAllocationState);
    return SUCCESS;
  }

  event result_t MemAlloc.compactComplete() {
    return SUCCESS;
  }

  /* --------------------------------- Message Queuing ---------------------------------*/
  /** Copy the specified bytes into the message queue.  Messages are always data
      (tuple) messages.  Messages of more than kMSG_LEN
      will be truncated.

      Legacy routine from days when we TupleRouterM used to maintain its own
      routing queue.  This has now been moved in low levels of the networking
      code.

      @param msg The data payload of the message to enqueue
      @param len The length (in bytes) of the data
      @return err_MessageSendFailed if the queue is full
  */
  command TinyDBError RadioQueue.enqueue(const QueryResultPtr qrMsg, bool *pending) {
	if (!IS_SENDING_MESSAGE())
	{
		QueryResultPtr newQrMsg;
		SET_SENDING_MESSAGE();
		
		newQrMsg = call Network.getDataPayLoad(&mMsg);
		*newQrMsg = *qrMsg;
		*pending = TRUE;
		mSendingResult = TRUE;
		//call PowerMgmtDisable();
		atomic {
		  mTimestampMsg = &mMsg;
		  mMustTimestamp = TS_QUERY_RESULT_MESSAGE;
		}
		if (call Network.sendDataMessage(&mMsg) != err_NoError) {
		  //call PowerMgmtEnable();
		  mSendFailed ++;
		  atomic {
		    mMustTimestamp = TS_NO;
		  }

#ifndef PLATFORM_PC
		  if (mSendFailed > MAX_FAILURES)
		    wdt_enable(WDTO_15MS);  //watchdog reset
#endif
		  
		  *pending = FALSE;
		  //outputDone(&mMsg);
		  UNSET_SENDING_MESSAGE();
		  mSendingResult=FALSE;
		  return err_MSF_SendWaitingBusy;
		} else 
		  mSendFailed = 0;
		
	}
	else {
	  *pending = FALSE;
	  return err_MSF_SendWaitingBusy;
	}
	return err_NoError;
  }

  /* --------------------------------- Error Handling  ---------------------------------*/
  #if defined(PLATFORM_PC) //itoa not on pc
  void itoa(int err, char *errNo, int radix) {
    errNo[0] = 0;
  }
  #endif

  command void signalError(TinyDBError err, int lineNo) {
    char errStr[sizeof(TOS_Msg)];
    char errNo[10],lineNoStr[10];

    
    //    int i, j, k, l;

    errStr[0] = 0;
#ifdef PLATFORM_PC
    dbg(DBG_USR3, "Error : %d at line %d\n", err, lineNo);
    dbg(DBG_USR2, "Error : %d at line %d\n", err, lineNo);    
    dbg(DBG_USR3, "Error : %d at line %d\n", err, lineNo);
    sprintf(errNo,"%d", err);

#else
    itoa(err, errNo, 10);
    itoa(lineNo, lineNoStr, 10);
#endif

    strcat(errStr, "Err: ");
    strcat(errStr, errNo);
    strcat(errStr, "(L:");
    strcat(errStr, lineNoStr);
    strcat(errStr, ")");
    strcat(errStr, "\0");
    
    call statusMessage(errStr);
  }
  
  bool mStatus;

  command void statusMessage(CharPtr m) {
    if (TOS_LOCAL_ADDRESS != 0) {
#ifdef kUART_DEBUGGER
      int len = strlen(m) >= 20?20:strlen(m);
      memcpy(mDbgMsg, m, strlen(m));
      atomic {
	mStatus = TRUE;
      }
      call UartDebugger.writeLine(mDbgMsg,(uint8_t)len);
#endif
      //call Network.sendUart(m,1 /* debugging msg id */);
    }
  }

#ifdef kUART_DEBUGGER
  async event result_t  UartDebugger.writeDone(char * string, result_t success) {
    atomic {
      if (mStatus) {
	mStatus = FALSE;
      } 
    }
    return SUCCESS;
  }
#endif
  
  /* --------------------------------- Event Handlers ---------------------------------*/


  event result_t CommandUse.commandDone(char *commandName, char *resultBuf, SchemaErrorNo err) {
    return SUCCESS;
  }
#ifdef kSUPPORTS_EVENTS
  event result_t EventFiredCommand.commandFunc(char *commandName, char *resultBuf, SchemaErrorNo *errorNo, ParamVals *params) {
    //find the appropriate query to fire...
    int qid = atoi(commandName);
    ParsedQuery *q;
    
    dbg(DBG_USR2,"got event command for query %d\n", qid);
    

    //is a valid query
    if (getQuery(qid, &q)) {
      dbg(DBG_USR2, "started query running\n");
      q->running = TRUE;
    }
    *errorNo = SCHEMA_SUCCESS;
    return SUCCESS;
  }

  event result_t EventUse.eventDone(char *name, SchemaErrorNo errorNo) {
    return SUCCESS;
  }
#endif

  /** Callback after we add a named field to the query schema
      Continue building the parsed query
  */
  event result_t Table.addNamedFieldDone(result_t success) {
    continueParsing(success);
    return SUCCESS;
  }

#ifdef kLIFE_CMD
  event result_t SetLifetimeCommand.commandFunc(char *commandName, char *resultBuf, SchemaErrorNo *errorNo, ParamVals *params) {
    dbg(DBG_USR2, "setting sample rate!\n");
    *errorNo = setSampleRateForLifetime(*(uint8_t *)params->paramDataPtr[0], *(uint16_t *)params->paramDataPtr[1]);

    if (*errorNo != SCHEMA_SUCCESS && *errorNo != SCHEMA_RESULT_PENDING)
      return FAIL;
    else {
      if (*errorNo == SCHEMA_RESULT_PENDING)
	mLifetimeCommandPending = TRUE;
      return SUCCESS;
    }
  }
#endif

  /* -- SRM --
  event result_t DBBuffer.bufferOpenForReading(uint8_t bufferId, bool success) {
    if (!success) {
    } else {
      finishedOpeningBufferForReading(mTempPQ, bufferId);
    }
  }

  event result_t DBBuffer.bufferOpenForWriting(uint8_t bufferId, bool success) {
    if (!success) {
      
    } else {
      finishedOpeningBufferForWriting(mTempPQ);
    }
  }
  */
  event result_t DBBuffer.resultReady(uint8_t bufferId) {
    return SUCCESS;
  }

  event result_t DBBuffer.getNext(uint8_t bufferId) {
    return SUCCESS;
  }

  event result_t DBBuffer.allocComplete(uint8_t bufferId, TinyDBError result) {
    if (result != err_NoError) {
#ifdef kUART_DEBUGGER
      //      call UartDebugger.writeLine("fail opened", 11);
#endif
      failedOpeningWriteBuffer(mTempPQ);
    }
    else {
#ifdef kUART_DEBUGGER
      //call UartDebugger.writeLine("alloc ok", 8);
#endif
      finishedOpeningWriteBuffer(mTempPQ);
    }
    return SUCCESS;
  }

  /* Signalled when a get is complete */
  event result_t DBBuffer.getComplete(uint8_t bufferId, QueryResult *buf, TinyDBError err) {
    //who to do with error?
    if (err != err_NoError) {
      TDB_SIG_ERR(err);
    } else {
#ifdef kUART_DEBUGGER
      if (TOS_LOCAL_ADDRESS != 0) call UartDebugger.writeLine("got ok", 6);
#endif
    }
    fillInAttrVal(SCHEMA_RESULT_READY);
    return SUCCESS;
  }
  
  /* Signalled when a put is complete */
  event result_t DBBuffer.putComplete(uint8_t bufferId, QueryResult *buf, TinyDBError err) {
    //keep enqueueing results
#ifdef kUART_DEBUGGER
    if (err == err_NoError) {
      //call UartDebugger.writeLine("put ok",6);
    } else {
      //call UartDebugger.writeLine("put fail",8);
    }
#endif
    post deliverTuplesTask();
    return SUCCESS;
  }

#ifdef kMATCHBOX
  event result_t DBBuffer.loadBufferDone(char *name, uint8_t id, TinyDBError err) {
    bool pending;

    if (err == err_NoError) {
      //call UartDebugger.writeLine("load ok",7);
    } else {
      //call UartDebugger.writeLine("load fail",9);
    }
    if (IS_OPENING_WRITE_BUF()) {
      mTempPQ->bufferId = id;
      if (err == err_NoError) {
	err = call DBBuffer.openBuffer(id, &pending);
	if (!pending || err != err_NoError) {
	  TDB_SIG_ERR(err);
	  finishedOpeningWriteBuffer(mTempPQ);
	}
      }
    } else {
      continueFromBufferFetch(err);
    }
    return SUCCESS;
  }

  event result_t DBBuffer.writeBufferDone(uint8_t bufId, TinyDBError err) {
    return SUCCESS;
  }

  event result_t DBBuffer.deleteBufferDone(uint8_t bufId, TinyDBError err) {
    return SUCCESS;
  }

  event result_t DBBuffer.cleanupDone(result_t success) {

    return SUCCESS;
  }
#endif

  event result_t DBBuffer.openComplete(uint8_t bufId, TinyDBError err) {
    if (err == err_NoError) {
      //call UartDebugger.writeLine("open ok",7);
    } else {
      //call UartDebugger.writeLine("open fail",9);
    }

    if (err!=err_NoError) {
      TDB_SIG_ERR(err);
    }
    finishedOpeningWriteBuffer(mTempPQ);
    return SUCCESS;
  }



  event result_t AttrUse.startAttrDone(uint8_t id)
  {
    mNumAttrs--;
    if (mNumAttrs == 0)
	{
      UNSET_STARTING_ATTRIBUTE();
	  fetchNextAttr();
	}
    return SUCCESS;
  }

#if defined(PLATFORM_MICA2) || defined(PLATFORM_MICA2DOT) || defined(PLATFORM_CRICKET)
  //this event indicates that the start symbol has been detected
  async event void RadioReceiveCoordinator.startSymbol(uint8_t bitsPerBlock, uint8_t offset, TOS_MsgPtr msgBuff) {
  }

  //this event indicates that another byte of the current packet has been rxd
  async event void RadioReceiveCoordinator.byte(TOS_MsgPtr msg, uint8_t byteCount) {
  }

  async event void RadioSendCoordinator.blockTimer() {
  }

  async event void RadioReceiveCoordinator.blockTimer() {
  }
  

  //this event indicates that the start symbol has been sent
#ifdef nodef
  async event void RadioSendCoordinator.startSymbol(uint8_t bitsPerBlock, uint8_t offset, TOS_MsgPtr msgBuff) {
    uint32_t *lowBytes;
    uint8_t *hiByte;
    uint16_t *clockCount;
    uint8_t qid;

    
    if (mMustTimestamp == TS_QUERY_MESSAGE) {
      QueryMessagePtr qm = call Network.getQueryPayLoad(mTimestampMsg);
      clockCount = &qm->clockCount;

      lowBytes = (uint32_t *)(&qm->timeSyncData[1]);
      hiByte = &qm->timeSyncData[0];
      qid = qm->qid;

    } else if (mMustTimestamp == TS_QUERY_RESULT_MESSAGE) {
      QueryResultPtr qr =  call Network.getDataPayLoad(mTimestampMsg);
      qid = qr->qid;
      clockCount = &qr->clockCount;
      lowBytes = (uint32_t *)(&qr->timeSyncData[1]);
      hiByte = &qr->timeSyncData[0];
      qr->lastDiff = mLastDiff;
      mLastDiff = 0;
    } else //TS_NO
      return;
    
    {
      tos_time_t cur_time = call Time.get();      
      ParsedQueryPtr pq;
      tos_service_schedule s = call ServiceScheduler.get(kTINYDB_SERVICE_ID);
      tos_time_t diff = call TimeUtil.subtract(s.start_time, cur_time);

      if (getQuery(qid, &pq)) {
	*hiByte = (uint8_t)(cur_time.high32 & 0x000000FF);
	*lowBytes = cur_time.low32;
	*clockCount = (uint16_t)(diff.low32 & 0x0000FFFF);
      }
      
      mMustTimestamp = TS_NO;
    }

  }
#endif


  //WARNING -- this code must be very short -- making it long
  // WILL lead to unexpected radio behaviors... For example, the version
  // causes loss rates to increase by 90% on MICA2DOTs
  async event void RadioSendCoordinator.startSymbol(uint8_t bitsPerBlock, uint8_t offset, TOS_MsgPtr msgBuff) {
#ifndef USE_LOW_POWER_LISTENING
    
    if (mMustTimestamp == TS_QUERY_MESSAGE) {
      tos_time_t cur_time = call Time.get();      
      tos_service_schedule s = call ServiceScheduler.get(kTINYDB_SERVICE_ID);
      tos_time_t diff = call TimeUtil.subtract(s.start_time, cur_time);
      
      QueryMessagePtr qm = call Network.getQueryPayLoad(mTimestampMsg);
      qm->clockCount = (uint16_t)(diff.low32 & 0x0000FFFF);
      *(uint32_t *)(&qm->timeSyncData[1]) = cur_time.low32;
      qm->timeSyncData[0] = (uint8_t)(cur_time.high32 & 0x000000FF);
    } else if (mMustTimestamp == TS_QUERY_RESULT_MESSAGE) {
      tos_time_t cur_time = call Time.get();      
      tos_service_schedule s = call ServiceScheduler.get(kTINYDB_SERVICE_ID);
      tos_time_t diff = call TimeUtil.subtract(s.start_time, cur_time);
      
      QueryResultPtr qr =  call Network.getDataPayLoad(mTimestampMsg);
      qr->clockCount = (uint16_t)(diff.low32 & 0x0000FFFF);  //clockCount
      *(uint32_t *)(&qr->timeSyncData[1]) = cur_time.low32; //lowBytes
      qr->timeSyncData[0] = (uint8_t)(cur_time.high32 & 0x000000FF); //hiByte
      qr->lastDiff = mLastDiff;  
    } else //TS_NO
      return;

    mLastDiff = 0;
    mMustTimestamp = TS_NO;
      


#endif /* USE_LOW_POWER_LISTENING */
  }


  //this event indicates that another byte of the current packet has been sent
  async event void RadioSendCoordinator.byte(TOS_MsgPtr msg, uint8_t byteCount) {
  }

#endif

#ifdef HSN_ROUTING
	command uint16_t HSNValue.getAdjuvantValue()
	{
		ParsedQuery *q;
		Expr *e;
		short i;
		QueryListHandle curQ;
		/* use aggregate adjuvant value if there is an aggregate query */
		for (curQ = mQs; curQ != NULL; curQ = (QueryListHandle)(**curQ).next) 
		{
			q = &(**curQ).q;
			for (i = 0; i < q->numExprs; i++)
			{
				e = call ParsedQueryIntf.getExprPtr(q, i);
				/* if it is an aggregate query */
				if (e->opType != kSEL)
					return mHSNValue;
			}
		}
		/* selection predicates are applied before packets are sent */
		return 1;
	}
#endif
}
