// $Id: TinyDBQuery.java,v 1.29 2003/10/07 21:46:07 idgay Exp $

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
package net.tinyos.tinydb;

import java.util.*;
import net.tinyos.message.*;

/** TinyDBQuery is a Java data structure representing a query running (or to be run)
 on a set of motes.
 
 Queries consist of:
 - a list of fields to select
 - a list of expressions over those fields, where an expression is
 - an filter that rejects some readings
 - an aggregate that combines local readings with readings from
 neighbors.

 In addition to allowing a query to be built, this class includes methods
 to generate radio messages so the query can be distributed over the network
 or to abort the query
 
 */
public class TinyDBQuery {
    
    /** Constructor
	 @param qid The id of the query
	 @param epochDur The rate (in ms) at which results from the query should be generated
	 */
    public TinyDBQuery(byte qid, int epochDur) {
		fields = new ArrayList();
		exprs = new ArrayList();
		this.qid = qid;
		this.from_qid = NO_FROM_QUERY;
		this.epochDur = (short)(epochDur / MS_PER_EPOCH_DUR_UNIT);
		this.numEpochs = 0;
    }
	

    /** Reload information about a detached query from the database
	 Note that you must still register as a listener for results
	 from this query to begin receiving results.
	 @param name The name of the query to restore
	 @param nw The network to instantiate the query in
	 @returns The restored query, or null if the query could not be found.
	 */
    public static TinyDBQuery restore(String name, TinyDBNetwork nw) {
		try {
			DBLogger db = new DBLogger();
			QueryState qs = db.restoreQueryState(name);
			if (qs != null) {
				TinyDBQuery q = net.tinyos.tinydb.parser.SensorQueryer.translateQuery(qs.queryString, (byte)qs.qid);
				if (q == null) return null;
				TinyDBMain.notifyAddedQuery(q);
				nw.setLastEpoch(qs.qid, qs.lastEpoch);
				if (qs.tableName != null) db.setupLoggingInfo(q, nw, qs.tableName);
				return q;
			} else return null;
			
		} catch (java.sql.SQLException e) {
			return null;
		} catch (net.tinyos.tinydb.parser.ParseException e) {
			//weird !
			return null;
		}
    }
	
    /** Write information about this query to the database, using
	 the specified name as the key with which it can be
	 restored.
	 @param name The name to save this query under
	 @param nw Network to fetch current query info from
	 @returns true iff the query was successfully saved.
	 */
	
    public boolean saveQuery(String name, TinyDBNetwork nw) {
		boolean ok = false;
		try {
			DBLogger db = DBLogger.getLoggerForQid(getId());
			if (db == null) db = new DBLogger();
			QueryState qs = new QueryState();
			
			qs.qid = getId();
			qs.queryString = getSQL();
			qs.lastEpoch = nw.getLastEpoch(getId());
			qs.tableName = db.getTableName();
			ok = db.saveQueryState(name, qs);
			db.close();
			
		} catch (java.sql.SQLException e) {
			//oh well
		}
		return ok;
    }
	
    /** Return the id of the query */
    public int getId() {
		return qid;
    }
	
    /** Set the id of the query.  Added by Kyle */
    public void setId(byte qid) {
		this.qid = qid;
    }
	
    /** Set the epoch duration of the query in ms*/
    public void setEpoch(int epochDur) {
	if (epochDur == kEPOCH_DUR_ONE_SHOT)
	    this.epochDur = kEPOCH_DUR_ONE_SHOT;
	else
	    this.epochDur = (short)(epochDur/MS_PER_EPOCH_DUR_UNIT);
    }


    /** Get the epoch duration of the query in ms*/
    public int getEpoch() {
	if (epochDur == kEPOCH_DUR_ONE_SHOT)
	    return kEPOCH_DUR_ONE_SHOT;
	else
	    return epochDur * MS_PER_EPOCH_DUR_UNIT;
    }
	
    /** Set the number of epochs for whicht this query will run*/
    public void setNumEpochs(short n) {
		this.numEpochs = n;
    }
	
    /** Add the specified field to the query */
    public void addField(QueryField f) {
		int idx = f.getIdx();
		
		/* Ick -- insure that the field is inserted at the correct
		 index (as indicated by f.getIdx)
		 
		 ArrayList.insureCapacity doesn't work, so explicitly insert nulls
		 for fields we haven't seen yet.
		 */
		int diff = (idx + 1) - fields.size();
		while (diff-- > 0)
			fields.add(null);
		
		try {
			fields.set(idx,f);
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
	
    /** Add the specified expression to the query */
    public void addExpr(QueryExpr e) {
	/*  Aggregate expressions must appear at the end of the expression list
	    or else the query won't run properly. */
	if (e.isAgg()) {
	    exprs.add(exprs.size(), e);
	    
	    AggExpr ae = (AggExpr)e;
	    
	    if (TinyDBMain.debug) System.out.println("ae's groupField = " + ae.getGroupField());
	    
	    if (ae.getGroupField() != AggExpr.NO_GROUPING) {
		isGrouped = true;
		groupExpr = ae;
	    }
	} else {
	    SelExpr se = (SelExpr)e;
	    //assume that whoever's submitting the query has already verified
	    //that this is a "proper" expression... -- e.g., if it's a string
	    //based query the types of the fields are strings
	    exprs.add(0,e);
	    lastSelExpr++;
	}
	
    }
	
    /** Return true if the query is grouped (e.g. contains one or more aggregates with a
	 group by expression)
	 */
    public boolean grouped() {
		return isGrouped;
    }
	
	public void setGrouped(boolean isGrouped) {
		this.isGrouped = isGrouped;
	}
	
  public void setGroupExpr(AggExpr ae) {
    groupExpr = ae;
  }
  
  public AggExpr getGroupExpr() {
    return groupExpr;
  }
  
    
  /** Return the name of the group by column */
  public String groupColName() {
    if (TinyDBMain.debug) System.out.println("isGrouped = " + isGrouped);
		
    if (isGrouped) {
      String fname = getField(groupExpr.getGroupField()).getName();
      
      return (fname + " " + ArithOps.getStringValue(groupExpr.getGroupFieldOp()) + " " + 
	      groupExpr.getGroupFieldConst());
    } else return null;
  }
  
    /** Return the text of the SQL for this query as set by setSQL (Note that TinyDBQuery does not
	 include an interface for generating SQL from an arbitrary query.)
	 */
    public String getSQL() {
		return sql;
    }
	
    /** Set the SQL string associated with this query.  Note that this string doesn't not neccessarily have
	 any relationship to the fields / expressions in this object
	 */
    public void setSQL(String s) {
		sql = s;
    }
    
    /** Return true if this query contains one or more aggregate expressions */
    public boolean isAgg() {
		Iterator i = exprs.iterator();
		while (i.hasNext()) {
			QueryExpr e = (QueryExpr)i.next();
			if (e.isAgg()) return true;
		}
		return false;
    }
	
    /* Return the number of expressions in this query */
    public int numExprs() {
	return exprs.size();
    }
    
    /* Return the ith expression in this query
       Expression are (currently) either selections or aggregates
       @throws ArrayIndexOutOfBoundsException if i < 0 or i >= numExprs()
    */
    public QueryExpr getExpr(int i) throws ArrayIndexOutOfBoundsException {
	try {
	    return (QueryExpr)exprs.get(i);
	} catch (IndexOutOfBoundsException e) {
	    throw new ArrayIndexOutOfBoundsException(i);
	}
    }
	
  /* Return the number of selection expressions in this query */
  public int numSelExprs() {
    return lastSelExpr+1;
  }

  /* Return the ith selection expression in this query
     @throws ArrayIndexOutOfBoundsException if i < 0 or i >= numSelExprs()
  */
  public QueryExpr getSelExpr(int i) throws ArrayIndexOutOfBoundsException {
    if (i >= numSelExprs() || i < 0) throw new ArrayIndexOutOfBoundsException(i);
    return (QueryExpr)exprs.get(i);
  }
  
    /* Replace the selection expressions with the ones in the specified
       vector.
       @throws IllegalArgumentException if an element of v is not a QueryExpr
       @throws ArrayIndexOutOfBoundsExcpetion if v.size() != numSelExprs()       
    */
    public void setSelExprs(Vector v) throws IllegalArgumentException, ArrayIndexOutOfBoundsException{
	if (v.size() != numSelExprs()) throw new ArrayIndexOutOfBoundsException();
	for (int i = 0; i < v.size(); i ++)
	    exprs.set(i, (QueryExpr)v.elementAt(i));
    }


    /* Display list of expressions contained in query */
    public String toString() {
		QueryExpr temp;
		String result = "";
		int i;
		
		result += "Fields in query:\n";
		
		for (i = 0; i < numFields(); i++)
			result += (i + "  " + getField(i) + "\n");
		
		result += numExprs() + " expressions representing query:\n";
		for (i = 0; i < numExprs(); i++) {
			try {
				temp = getExpr(i);
				result += temp;
			} catch (IndexOutOfBoundsException e) {}
		}
		result += "Epoch Duration = " + epochDur + "\n";
		result += "Query ID = " + qid + "\n";
		
		return result;
    }
	
    /** Returns true iff the query contains a field that isn't contained in any aggregate.
	 NOTE:  Will return FALSE in this example "Select light, avg(light) from sensors"
	 But, tinydb processes this query if it were "Select avg(light) from sensors"
	 */
    public boolean containsNonAggFields() {
		QueryField qf;
		QueryExpr qe;
		boolean isAggField;
		
		for (int i = 0; i < numFields(); i++) {
			qf = getField(i);
			isAggField = false;
			for (int expIndx = 0; expIndx < numExprs(); expIndx++) {
				qe = getExpr(expIndx);
				
				//if the query field is found in an aggregate expression
				if ((qe.getField() == qf.getIdx()) && qe.isAgg())
					isAggField = true;
			}
			if (!isAggField) return true;
		}
		
		return false;
    }
	
	
    public void setOutputCommand(String cmd, short param) {
		hasCmd = true;
		paramVal = param;
		cmdName = cmd;
		hasParam = false;
    }
	
    public void setOutputCommand(String cmd) {
		setOutputCommand(cmd, (short)0);
		hasParam = false;
    }
	
    
    public boolean hasOutputAction() {
		//if we're logging results or executing a commands, we won't hear values over the radio
		return hasCmd || hasName;
    }
    
	
    public boolean hasEvent() {
		return hasEvent;
    }
	
    public String getEvent() {
		if (hasEvent)
			return eventName;
		else
			return null;
    }
	
    public void setEvent(String name) {
		hasEvent = true;
		eventName = name;
    }
	
    /** Return the number of fields in this query */
    public int numFields() {
		return fields.size();
    }
    
    /** Return the ith field in this query
	 @throws ArrayIndexOutOfBoundsException if i < 0 or i >= numFields()
	 */
    public QueryField getField(int i) throws ArrayIndexOutOfBoundsException {
		try {
			return (QueryField)fields.get(i);
		} catch (IndexOutOfBoundsException e) {
			throw new ArrayIndexOutOfBoundsException(i);
		}
    }
	
    /** Return a byte array representing a radio message that will tell
	 motes to abort this query */
    public Message abortMessage() {
	
	QueryMsg m = new QueryMsg();
	initCommonFields(m);
	m.set_u_ttl(DEL_MSG_TTL);
	m.set_msgType(DEL_MSG);
	return m;
    }
	
    /** Return a message that, when injected, will change the rate of
	 a currently running query.
	 */
    public Message setRateMessage(int rate) {
	QueryMsg m = new QueryMsg();
	initCommonFields(m);
	m.set_msgType(SET_RATE_MSG);
	this.epochDur = (short)(rate / MS_PER_EPOCH_DUR_UNIT);
	m.set_epochDuration(epochDur);
	return m;
    }

    public void setDropTables() {
	this.dropTables = true;
	
    }
	
    /* Return a vector of strings containing the
	 headings for the columns in this query
	 */
    public Vector getColumnHeadings() {
		Vector cols = new Vector();
		boolean addedGroupCol = false;
		
		cols.addElement("Epoch");
		
		if (isAgg()) {
			//it's an agg; the columns that are returned
			//are the group and the aggregate value
			for (int i = 0; i < numExprs(); i++) {
				QueryExpr e = getExpr(i);
				
				//System.out.println("Expression " + i + " is " + e.isAgg() + "   " + e);
				
				if (e.isAgg()) {
					AggExpr ae = (AggExpr)e;
					if (ae.getGroupField() != -1 && !addedGroupCol) {
						cols.addElement(groupColName());
						addedGroupCol = true;
					}
					String aggString = "";
					aggString += ae.getAgg().toString() + "(" + getField(ae.getField()).getName();
					
					if (ae.getFieldOp() != ArithOps.NO_OP) {
						aggString += ArithOps.getStringValue(ae.getFieldOp()) + " ";
						aggString += ae.getFieldConst();
					}
					
					aggString += ")";
					
					cols.addElement(aggString);
					
				}
				if (TinyDBMain.debug) System.out.println(cols);
			}
			
		} else {
			//its a selection; the columns that are returned
			//are the exprs
			for (int i =0; i < numFields(); i++) {
				QueryField qf = getField(i);
				if (qf != null) cols.addElement(qf.getName());
			}
			
		}
		
		return cols;
    }
	
    //Returns the type (as defined in QueryField) of the specified
    //column in the result set.
    public byte getFieldType(int idx) throws ArrayIndexOutOfBoundsException {
		boolean addedGroupCol = false;
		if (idx == 0) return QueryField.INTTWO;
		if (isAgg()) {
			for (int i = 0; i < numExprs(); i++) {
				QueryExpr e = getExpr(i);
				
				if (e.isAgg()) {
					AggExpr ae = (AggExpr)e;
					if (ae.getGroupField() != -1 && !addedGroupCol) {
						if (--idx == 0) return getField(groupExpr.getGroupField()).getType();
						addedGroupCol = true;
					}
					if (--idx == 0) return getField(ae.getField()).getType();
				}
				
			}
			throw new ArrayIndexOutOfBoundsException();
		} else {
			for (int i = 0; i < numFields(); i++) {
				QueryField qf = getField(i);
				if (--idx == 0) return qf.getType();
			}
			throw new ArrayIndexOutOfBoundsException();
		}
		
    }
	
    
    /** Return an Iterator over messages to be sent
	 to start sensors running this
	 query
	 */
    public Iterator messageIterator() {
		ArrayList messages = new ArrayList();
		Message msg;
		QueryMsg qrm;
		
		//first, set up all the fields
		for (int i = 0; i < fields.size(); i++) {
			QueryField f = (QueryField)fields.get(i);
			
			qrm = new QueryMsg();
			msg = qrm;
			initCommonFields(qrm);
			qrm.set_type(FIELD);
			qrm.set_idx((byte)i);
			qrm.set_u_field_op(f.getOp());
			qrm.setString_u_field_name(f.getName());
			qrm.set_u_field_type(f.getType());
			if (TinyDBMain.debug) System.out.println(qrm.toString());
			
			messages.add(msg);
		}
		
		//then all the exprs
		for (int i = 0; i < exprs.size(); i++) {
			QueryExpr e = (QueryExpr)exprs.get(i);
			
			qrm = new QueryMsg();
			msg = qrm;
			initCommonFields(qrm);
			
			qrm.set_type(EXPR);
			qrm.set_idx((byte)i);
			qrm.set_u_expr_opType((byte)(e.isAgg()?(((AggExpr)e).isTemporalAgg()?TEMPORAL_AGG_EXPR:AGG_EXPR):SEL_EXPR));
			
			
			qrm.set_u_expr_fieldOp(e.getFieldOp());
			qrm.set_u_expr_fieldConst(e.getFieldConst());
			if (e.isAgg()) {
				AggExpr a = (AggExpr)e;
				
				qrm.set_u_expr_ex_agg_field(e.getField());
				qrm.set_u_expr_ex_agg_op(a.getAggOpCode());
				qrm.set_u_expr_ex_agg_groupingField(a.getGroupField());
				qrm.set_u_expr_ex_agg_groupFieldOp(a.getGroupFieldOp());
				qrm.set_u_expr_ex_agg_groupFieldConst(a.getGroupFieldConst());
			
				// set up arguments, for both temporal and non-temporal ones
				AggOp ag = a.getAgg();//needs renaming?
				for (int j=0; j < ag.getArguments().size(); j++) {
					qrm.setElement_u_expr_ex_tagg_args(j, ag.getArgument(j));
				}
			} else {
				SelExpr s = (SelExpr)e;
				
				if (s.isString()) {
					qrm.set_u_expr_isStringExp((byte)1);
					qrm.set_u_expr_ex_sexp_field(e.getField());
					qrm.set_u_expr_ex_sexp_op((byte)s.getSelOpCode());
					qrm.setString_u_expr_ex_sexp_s(s.getStringConst());
				} else {
					qrm.set_u_expr_isStringExp((byte)0);
					qrm.set_u_expr_ex_opval_field(e.getField());
					qrm.set_u_expr_ex_opval_op((byte)s.getSelOpCode());
					qrm.set_u_expr_ex_opval_value(s.getValue());
				}
			}
			if (TinyDBMain.debug) {
				System.out.println("expr msg: ");
				System.out.print(qrm.toString());
			}
			messages.add(msg);
		}
		
		//the command, if this is a command buffer
		if (hasCmd) {
		    qrm = new QueryMsg();
		    msg = qrm;
			initCommonFields(qrm);
			qrm.set_type(BUFFER);
			qrm.setString_u_buf_cmd_name(cmdName);
			qrm.set_u_buf_cmd_hasParam((short)(hasParam?1:0));
			qrm.set_u_buf_cmd_param(paramVal);
			if (TinyDBMain.debug) System.out.println("command msg: " + qrm.toString());
			messages.add(msg);
		} else if (ramBuffer) { //or, might be a ram buffer
		    qrm = new QueryMsg();
		    msg = qrm;
			initCommonFields(qrm);
			qrm.set_type(BUFFER);
			qrm.set_u_buf_ram_numRows(bufSize);
			qrm.set_u_buf_ram_policy(EVICT_OLDEST_POLICY);
			qrm.set_u_buf_ram_create(createTable?(byte)1:(byte)0);
			qrm.set_u_buf_ram_hasOutput(hasName?(byte)1:(byte)0);
			qrm.setString_u_buf_ram_outBufName(queryName);
			qrm.set_u_buf_ram_hasInput(hasInputBuf?(byte)1:(byte)0);
			qrm.setString_u_buf_ram_inBufName(inputBufferName);
			if (TinyDBMain.debug) System.out.println("ram buffer msg: " + qrm.toString());
			messages.add(msg);
		}
		
		//if this query is triggered by an event, send in the event
		if (hasEvent) {
		    qrm = new QueryMsg();
		    msg = qrm;
			initCommonFields(qrm);
			qrm.set_type(EVENT);
			qrm.setString_u_eventName(eventName);
			if (TinyDBMain.debug) System.out.println("event message: " + qrm.toString());
			messages.add(msg);
		}
		
		//if this query is for a fixed number of epochs, send the number of epochs
		if (numEpochs > 0) {
		    qrm = new QueryMsg();
		    msg = qrm;
			initCommonFields(qrm);
			qrm.set_type(N_EPOCHS);
			qrm.set_u_numEpochs(numEpochs);
			if (TinyDBMain.debug) System.out.println("num epochs message: " + qrm.toString());
			messages.add(msg);
		}

		//if this is a drop message, that's it
		if (dropTables) {
		    qrm = new QueryMsg();
		    msg = qrm;
		    initCommonFields(qrm);
		    qrm.set_msgType(DROP_TABLE);			
		    if (TinyDBMain.debug) System.out.println("drop message: " + qrm.toString());
		    qrm.set_u_ttl(DEL_MSG_TTL);
		    messages.add(msg);
		}

		
		return messages.iterator();
    }
	
    // set up common fields in radio messages
    private void initCommonFields(QueryMsg m) {

      m.set_msgType(ADD_MSG);
      m.set_qid(qid);
      m.set_fwdNode(TinyDBNetwork.UART_ADDR); 
      m.set_numFields((byte)fields.size());
      m.set_numExprs((byte)exprs.size());
      m.set_fromCatalogBuffer(fromCatalogBuf?(byte)1:(byte)0);
      m.set_fromBuffer(fromCatalogBuf?catalogTableId:from_qid);
      
      m.set_bufferType(hasCmd?COMMAND_BUFFER:(ramBuffer?EEPROM_BUFFER:RADIO_BUFFER));

      m.set_epochDuration(epochDur);
      if (hasEvent)
	  m.set_hasEvent((byte)1);
      else
	  m.set_hasEvent((byte)0);
      if (numEpochs > 0)
	  m.set_hasForClause((byte)1);
      else
	  m.set_hasForClause((byte)0);
      for (int i = 0; i < 5; i++) {
	  m.setElement_timeSyncData(i, (short)0);
      }
      m.set_clockCount((short)0);
    }
	
    /* Return the id fo the query this query reads results from */
    public byte getFromQid() {
		return from_qid;
    }
    
    /** Set the id of the query this query reads results from */
    public void setFromQid(byte qid) {
		this.from_qid = qid;
    }
	
	public void setFromCatalogTable(byte catalogTable) {
		this.fromCatalogBuf = true;
		this.catalogTableId = catalogTable;
	}
	
    public boolean isFromCatalogTable() {
		return fromCatalogBuf;
    }
    
    /** Specify that this query should output results to a RAM based buffer */
	public void useRamBuffer(short size) {
		bufSize = size;
		ramBuffer = true;
	}
    
    /** Specify the name of the buffer this query outputs results to -- other queries
	 may refer to this buffer name.  If share is true, associate this name with
	 this query (globally), so that other queries can reference the local schema.
	 */
    public void setBufferName(String name, boolean share) {
	//overwrite old values, if they exist...
	if (share) nameHashMap.put(name.toLowerCase(), this);
	this.queryName = name;
	hasName = true;
    }
	
    public void setInputBufferName(String name) {
		this.inputBufferName = name;
		hasInputBuf = true;
    }
	
    /** Given a buffer name, lookup the query which corresponds to it. */
    public static TinyDBQuery getQueryForBufName(String name) {
		return (TinyDBQuery)nameHashMap.get(name.toLowerCase());
    }
	
    public void setBufferCreateTable(boolean create) {
		createTable = create;
    }
	
    public boolean getBufferCreateTable() {
		return createTable;
    }
	
	
    /** Inactive queries have been "stopped" -- e.g. cancelled on the motes,
	 but we may still want to keep state about them so the can be
	 restarted at the previous epoch
	 */
    public boolean active() {
		return isRunning;
    }
	
    public void setActive(boolean active) {
		isRunning = active;
    }
	
    
    
    public byte qid,from_qid;
    private short epochDur;
	public short numEpochs;
	
	private boolean fromCatalogBuf = false;
	private byte catalogTableId;
	
    private static HashMap nameHashMap = new HashMap();
	
    private boolean ramBuffer = false;
    private short bufSize;
	
    private boolean isGrouped = false;
    private AggExpr groupExpr = null;
	
    private ArrayList fields;
    private ArrayList exprs;
    private int lastSelExpr = -1;
	
    private String sql = "";
	
    private boolean hasCmd = false;
    private String cmdName;
    private short paramVal = 0;
    private boolean hasParam = false;
    private String queryName = "";
    private String inputBufferName = "";
    private boolean hasName = false;
    private boolean hasInputBuf = false;
	
    private boolean hasEvent = false;
    private boolean createTable = false;
    
    private boolean dropTables = false;

    private String eventName;
    
    static final byte FIELD = 0;
    static final byte EXPR = 1;
    static final byte BUFFER = 2;
    static final byte EVENT = 3;
    static final byte N_EPOCHS = 4;
    static final byte DROP_TABLE = 5;

    static final byte ADD_MSG = 0;
    static final byte DEL_MSG = 1;
    static final byte MODIFY_MSG = 2;
    static final byte SET_RATE_MSG = 3;
	
    static final byte DEL_MSG_TTL = 3; //ttl on delete messages
    
    public static final byte NO_FROM_QUERY = (byte)0xFF;
	
    static final byte SEL_EXPR = 0;
    static final byte AGG_EXPR = 1;
    static final byte TEMPORAL_AGG_EXPR = 2;
	
    static final byte RADIO_BUFFER = 0;
    static final byte RAM_BUFFER = 1;
    static final byte EEPROM_BUFFER = 2;
    static final byte COMMAND_BUFFER = 3;
    static final byte ATTRLIST = 4;
    static final byte EVENTLIST = 5;
    static final byte COMMANDLIST = 6;
    static final byte QUERYLIST = 7;
    static final byte EVICT_OLDEST_POLICY = 0;

    static final short MS_PER_EPOCH_DUR_UNIT =10;
    
    public static final short kEPOCH_DUR_ONE_SHOT=(short)0x7FFF;
	
    private boolean isRunning = false; //have we seen any results for this query lately?
	
}
