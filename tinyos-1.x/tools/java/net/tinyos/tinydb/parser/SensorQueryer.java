// $Id: SensorQueryer.java,v 1.6 2003/10/07 21:46:08 idgay Exp $

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
package net.tinyos.tinydb.parser;

import net.tinyos.tinydb.*;
import java.io.*;
import java_cup.runtime.*;
import java.util.Hashtable;

public class SensorQueryer {
    private static boolean DEBUG = false;
    
    private TinyDBNetwork network;
    private byte queryId = 1;
    public static String errorMessage = "";
    
    public SensorQueryer(TinyDBNetwork network) {
	this.network = network;
    }
    
    public void query(String sql_query) {
	TinyDBQuery tdb_query;
	
	try {
	    tdb_query = translateQuery(sql_query, queryId++);
	} catch (ParseException pe) {
	    System.err.println(pe.getMessage());
	    pe.printStackTrace();
	    System.err.println(pe.getParseError());
	    return;
	}
	try {
	    network.sendQuery(tdb_query);
	} catch (IOException e) {
	    e.printStackTrace();
	}
    }
    
    public static TinyDBQuery translateQuery(String sql_query, byte queryId) throws ParseException {
	StringReader reader = new StringReader(sql_query);
	senseParser parser = new senseParser(new Yylex(reader));
	Symbol parse_result = null;
	
	if (parser == null)
	    System.out.println("PARSER IS NULL");
	//parser.setCatalog("catalog");
	//parser.setQueryId(queryId);
	
	try {
	    errorMessage = "";
	    if (DEBUG)
		parse_result = parser.debug_parse();
	    else
		parse_result = parser.parse();
	} catch (Exception e) {
	    String parseErrMessage;
	    if (errorMessage.equals(""))
		parseErrMessage = parser.errorMsg;
	    else
		parseErrMessage = errorMessage;
	    throw new ParseException(e, parseErrMessage);
	}
	
	String status;
	TinyDBQuery tdb_query = (TinyDBQuery) parse_result.value;
	tdb_query.setId(queryId);
	tdb_query.setSQL(sql_query);

	status = checkValidQuery(tdb_query);

	//System.out.println("Query Status:  " + status);
	
	if (status.equals("ok")) {
	    return tdb_query;
	} else {
	    throw new ParseException(new Exception("Inconsistent Query: " + status), status);
	    //return null;
	}	    
    }
    
    private static String checkValidQuery(TinyDBQuery tdb_query) {
	boolean hasNonAggs = false;
	boolean isAggQuery = tdb_query.isAgg();  //true if >0 aggregate expressions
	boolean isGrouped = false;  //true if isAggQuery and has a group by expression
	Hashtable fields = new Hashtable();

	//hasNonAggs isn't being set right
	//currently set to true only if a non-aggregate expression is present (not a non-aggregate field)

	if (tdb_query.numExprs() > 0) {
	    QueryExpr e = tdb_query.getExpr(0);
	    System.out.println("Expression: " + e);
	    if (!e.isAgg()) hasNonAggs = true;
	}


	if (tdb_query.grouped() && !isAggQuery)
	    return "Can't group by if there are no aggregates!";

	for (int i = 0; i < tdb_query.numExprs();i++) {
	    QueryExpr e = tdb_query.getExpr(i);
	    if (e.isAgg()) {
		if (tdb_query.grouped() && ((AggExpr)e).getField() == tdb_query.getGroupExpr().getGroupField())
		    return "Can't group by aggregate field.";
		fields.put(new Integer(((AggExpr)e).getField()), new Integer(0));
		fields.put(new Integer(((AggExpr)e).getGroupField()), new Integer(0));
	    } else
		fields.put(new Integer(((SelExpr)e).getField()), new Integer(0));
	}
	
	if (isAggQuery) {
	    for (int i = 0; i < tdb_query.numFields(); i++) {
		QueryField qf = tdb_query.getField(i);
		if (fields.get(new Integer(qf.getIdx())) == null)
		    return "Can't SELECT non-aggregate fields in aggregate query.";
	    }
	}
	 	
	return "ok";
    }
}

