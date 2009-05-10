// $Id: DBLogger.java,v 1.12 2003/10/30 23:27:33 smadden Exp $

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

import java.sql.*;
import java.util.*;

/** DBLogger is repsonsible for logging query results to Postgres.
    When instantiated with a query, it creates a new table to
    hold the results of that query and registers itself as a listener
    to results from that query.

    The name of table that is logged to can be retrieved via the 
    getTableName() method.  It will be uniquely generated for each
    query.

    The schema of the results table is:

   +----------------------------------------------------------+
   |  time stamp  | epoch no  |  field1 |  .... |  field n    |
   +----------------------------------------------------------+


   Additionally, each query is logged to a queries table (which must have been
   created before DBLogger is invoked.  The command to insert the queries table
   is:
   
   create table queries (qname varchar(10), query_time timestamp, query_string varchar(500));
*/


public class DBLogger implements ResultListener, QueryListener
{


    private Connection conn = null;
    private static String urlPSQL= "jdbc:postgresql:";
    private static String m_usr = Config.getParam("postgres-user");
    private static String m_pwd = Config.getParam("postgres-passwd");;
    private final static String insertQueryStmt = "INSERT INTO queries values (?, ?, ?)";
    private TinyDBQuery queryToLog;
    private String queryString;
    private long queryTime;
    private Statement stmt;
    private String logTableName;
    private TinyDBNetwork network;
    private boolean dupElim = false;
    private static Hashtable loggers = new Hashtable();

    /* ------------------------------------- Public Methods ------------------------------------------ */


    /** Create a DBLogger for accessing the database
	without a query to log (e.g. to restore a query from
	the DB.
    */
    public DBLogger() throws SQLException {
	initDBConn();
	if (stmt == null) throw new SQLException("Open fialed.");
	queryToLog = null;
	queryString = null;
	network = null;
	queryTime = 0;
	logTableName = null;
    }

    /** Set the parameters that this logger needs to start logging
	data for a particular query.  Note that this allows us
	to append onto an existing result table, and will not
	work if that result table hasn't already been created.
    */
    void setupLoggingInfo(TinyDBQuery qToLog, TinyDBNetwork nw, String logTable) {
	queryToLog = qToLog;
	this.network = nw;
	queryTime = System.currentTimeMillis();
	logTableName = logTable;
	nw.addResultListener(this, true, qToLog.getId());
	loggers.put (new Integer(qToLog.getId()), this);
    }
    
    /** Start logging the specified query
	@param query The query to log
	@param queryStr The SQL string corresponding to query (since not all TinyDB queries have a unique
	                SQL representation)
	@param nw The TinyDBNetwork that will deliver results for this query
	@throw SQLExcpetion if logging failed
    */
    public DBLogger(TinyDBQuery query, String queryStr, TinyDBNetwork nw) throws SQLException
    {
	initDBConn();
	queryToLog = query;
	queryString = queryStr;
	network = nw;
	queryTime = System.currentTimeMillis();
	logTableName =  uniqueName();
	logQuery();
	nw.addResultListener(this, true, query.getId());
	loggers.put(new Integer(query.getId()), this);
    }

    /** @return The name of the table to which this queries results are being logged */
    public String getTableName() {
	return logTableName;
    }

    /** Toggle whether duplicate elimination is done on inserts
	@param enable If true, duplicate elimination will be enabled, otherwise it will be disabled
    */
    public void setDupElim(boolean enable) {
	dupElim = enable;
    }

    /** ResultListener Method.  Log the specified query result to the table set up for
	this DBLogger.
	@param qr The result to log
    */
    public void addResult(QueryResult qr)
    {
	String sqlStr = insertStmt(qr, logTableName);
	if (stmt == null) return;

	if (TinyDBMain.debug) System.out.println("logging result: " + sqlStr);
	try
	    {
		boolean isDup = false;
		

		if (dupElim) {
		    stmt.execute("BEGIN TRANSACTION");
		    //check and see if this is a duplicate row
		    // note that if there are multiple writers, this does
		    // not guarantee that there will be no duplicates, as 
		    // both could check and not detect any duplicates before
		    // writing the update, but...
		    System.out.println("CHECKING FOR DUPLICATES.");
		    Integer name = (Integer)qr.getFieldObj("nodeid");
		    if (name != null) {
			
			String dupCheckStmt = "SELECT * FROM " + logTableName + " WHERE nodeid = " 
			    + name + " AND epoch = " + qr.epochNo();
			ResultSet rs;
			rs = stmt.executeQuery(dupCheckStmt);
			isDup = (rs.first());
			if (isDup) System.out.println("WAS DUPLICATE : " + dupCheckStmt);
		    }
		}

		//only update if this isn't a duplicate, or we're not checking for dups
		if (!isDup) stmt.executeUpdate(sqlStr);
		if (dupElim) stmt.execute("END TRANSACTION");
	    }
	catch (SQLException e)
	    {
		System.err.println("INSERT Result for query " + queryToLog.getId() + " failed.  SQLState = " + e.getSQLState());
	    }
    }

    /** QueryListener Method.  Stop logging for the specified query.
	@param q The query to stop logging for
    */
    public void removeQuery(TinyDBQuery q) {
	if (q == queryToLog) {
	    close();
	}
    }

    public boolean saveQueryState(String name, QueryState s) {
	String insertState = "INSERT INTO queryState VALUES(";
	String replaceState = "DELETE FROM queryState WHERE name = '" + name + "'";

	if (stmt == null) return false;

	try {
	    String queryStateTable = "CREATE TABLE queryState (name varchar(20), qid int, queryString varchar(200), lastEpoch int, logTableName varchar(20))";
	    stmt.executeUpdate(queryStateTable);
	} catch (SQLException e) {
	    //trust that it now exists
	}
	try {
	    stmt.executeUpdate(replaceState);
	} catch (SQLException e) {
	    //remove old state for this query name
	}
	try {
	    insertState += "'" + name + "'," + s.qid + ",'" + s.queryString + "'," + s.lastEpoch + ",";
	    if (s.tableName == null) insertState += "null)";
	    else insertState += "'" + s.tableName + "')";
	    System.out.println("executing : " + insertState);
	    stmt.executeUpdate(insertState);
	} catch (SQLException e) {
	    System.out.println("Failed to save state.");
	    if (TinyDBMain.debug) e.printStackTrace();
	    return false;
	}
	return true;
    }

    public QueryState restoreQueryState(String name) {
	String getStateQuery = "SELECT qid,queryString,lastEpoch,logTableName FROM queryState WHERE name = '" + name +"'";

	if (stmt == null) return null;

	try {
	    QueryState qs = new QueryState();
	    ResultSet rs;

	    rs = stmt.executeQuery(getStateQuery);
	    if (rs.first() == false) return null;
	    qs.qid = rs.getInt(1);
	    qs.queryString = rs.getString(2);
	    qs.lastEpoch = rs.getInt(3);
	    qs.tableName=rs.getString(4); //note: may be null!
	    System.out.println("RESTORING -- lastEpoch = " + qs.lastEpoch + ", tableName = " + 
			       qs.tableName + ", qid + " +qs.qid);
	    return qs;

	} catch (SQLException e) {
	    System.out.println("Restore query state failed.");
	    e.printStackTrace();
	    return null;
	}
    }
    
    /** QueryListener Method.  Does nothing.  */
    public void addQuery(TinyDBQuery q) {
    }

    /** Shut down the connection to Postgres. */
    public void close()
    {
	if (network != null) network.removeResultListener(this);
	try
	    {
		if (conn != null)
		    conn.close();
		conn = null;
		if (TinyDBMain.debug)  System.out.println("disconnected from postgres.");
	    }
	catch (Exception e)
	    {
	    }
    }

    public static DBLogger getLoggerForQid(int qid) {
	return (DBLogger)loggers.get(new Integer(qid));
    }


    /* ------------------------------------- Private Methods ------------------------------------------ */
    /** Open the connection to Postgres */
    private void initDBConn()
    {
	try {
	    urlPSQL += "//" + Config.getParam("postgres-host") + "/" + Config.getParam("postgres-db");
	    Class.forName ( "org.postgresql.Driver" );
	    conn = DriverManager.getConnection(urlPSQL, m_usr, m_pwd);
	    stmt = conn.createStatement();
	    if (TinyDBMain.debug) System.out.println("connected to " + urlPSQL);
	} catch (Exception ex) {
	    System.out.println("failed to connect to Postgres!\n");
	    stmt = null;
	    ex.printStackTrace();
	}
	if (TinyDBMain.debug) System.out.println("Connected to Postgres!\n");
    }

    /** Do the setup work for starting to log a query
	@throw SQLException if an error occurred creating / logging a query 
    */
    private void logQuery() throws SQLException 
    {
	try
	    {
		PreparedStatement  pstmt = null;
		pstmt = conn.prepareStatement(insertQueryStmt);
		pstmt.setString(1, getTableName());
		pstmt.setTimestamp(2, new Timestamp(queryTime));
		pstmt.setString(3, queryString);
		pstmt.executeUpdate();
		pstmt.close();
	    }
	catch (SQLException ex) {
	    System.out.println("logQuery failed.\n");
	    ex.printStackTrace();
	    throw ex;
	}
	// create log table for the query
	String dropOldTable = "DROP TABLE " + logTableName;
	try {
	    stmt.executeUpdate(dropOldTable);
	} catch (SQLException e){
	    //ignore exceptions
	}

	String createTabStr = createTableStmt(queryToLog, logTableName);
	if (TinyDBMain.debug) System.out.println(createTabStr);
	try
	    {
		stmt.executeUpdate(createTabStr);
	    }
	catch (SQLException e)
	    {
		System.err.println("INSERT Result for query " + queryToLog.getId() + " failed.  SQLState = " + e.getSQLState());
		throw e;
	    }
    }

	public static String createTableStmt(TinyDBQuery query, String tableName)
	{
		String createTabStr = "CREATE TABLE " + tableName + "(result_time timestamp";
		Vector columns = query.getColumnHeadings();
		for (int i = 0; i < columns.size(); i++)
	    {
			String colName = (String)columns.elementAt(i);
			createTabStr += ", ";
			
			createTabStr += colName.replace('(','_').replace(')',' ').trim();
			createTabStr += " ";
			if (query.getFieldType(i) == QueryField.STRING)
				createTabStr += "varchar(32)"; // XXX should be sufficient for now
			else if (query.getFieldType(i) == QueryField.BYTES)
				createTabStr += "bytea";
			else
				createTabStr += "int";
	    }
		createTabStr += ")";
		return createTabStr;
	}

    public static String insertStmt(QueryResult qr, String tableName)
    {
	String sqlStr = "INSERT INTO " + tableName + " VALUES (now()";
	Vector resultVector = qr.resultVector();
	TinyDBQuery query = qr.getQuery();
	
	for (int i = 0; i < resultVector.size(); i++)
	    {
		String str;
		if (resultVector.elementAt(i) == null)
		    str = "null";
		else
		    str = resultVector.elementAt(i).toString();
		if (query.getFieldType(i) == QueryField.BYTES)
		    str = toOctal((byte[])resultVector.elementAt(i));
		sqlStr += ", ";
		if (str == null)
		    sqlStr += "NULL";
		else
		    {
			if (query.getFieldType(i) == QueryField.STRING ||
			    query.getFieldType(i) == QueryField.BYTES)
			    sqlStr += "'";
			sqlStr += str;
			if (query.getFieldType(i) == QueryField.STRING ||
			    query.getFieldType(i) == QueryField.BYTES)
			    sqlStr += "'";
		    }
	    }
	sqlStr += ")";
	return sqlStr;
    }
    
    private static String toOctal(byte[] b) {
	String retVal = "";
	int pad;
	if (b == null) return "null";
	for (int i = 0; i < b.length; i++) {
	    //System.out.print("b[" + i + "] = " + b[i]);
	    if (b[i] == -1) b[i] = 0; //HACK!
	    String s= Integer.toString((int)b[i]&0xFF,8); //unsign first
	    pad = 3 - s.length();
	    retVal += "\\\\";
	    while (pad-- > 0)
		retVal += "0";
	    retVal += s;
		
	}
	System.out.println("");
	return retVal;
    }
    

    /** Generate a unique name for a new query result table */
    private String uniqueName() throws SQLException {
	String createSeqNoTab = "CREATE TABLE seqno (seqno int)";
	String makeSeqNo = "INSERT INTO seqno VALUES(0)";
	String getSeqNo = "SELECT seqno FROM seqno";
	String setSeqNo = "UPDATE seqno SET seqno = ";
	ResultSet rs;
	int seqNo = 0;
	boolean didCreate = false;
	
	if (stmt == null) throw new SQLException("Connection is not open.");

	if (TinyDBMain.debug) System.out.println("Trying to create seqno table:" + createSeqNoTab);
	try {
	    stmt.executeUpdate(createSeqNoTab);
	    //note that the above statement will generate an exception if the table already exists!
	    didCreate = true;
	} catch (SQLException e) { //ignore exceptions
	}


	try {
	    if (didCreate)
		stmt.executeUpdate(makeSeqNo);
	    if (TinyDBMain.debug) System.out.println("Fetching seqno:" + getSeqNo);
	    rs = stmt.executeQuery(getSeqNo);
	    rs.first();
	    seqNo = rs.getInt(1);
	    seqNo++;
	    setSeqNo += seqNo;
	    if (TinyDBMain.debug) System.out.println("Setting seqno:" + setSeqNo);
	    stmt.executeUpdate(setSeqNo);
	} catch (SQLException e) {
	    if (TinyDBMain.debug) System.out.println("Error fetching/setting seqNo:" + e);
	    throw e;
	}
	
	return "q"+seqNo;
	
	
    }


}
