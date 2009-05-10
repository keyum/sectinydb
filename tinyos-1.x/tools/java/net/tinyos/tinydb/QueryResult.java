// $Id: QueryResult.java,v 1.25 2003/10/30 23:28:14 smadden Exp $

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
import net.tinyos.util.ByteOps;
//import net.tinyos.gdi.GDI2SoftConverter;

/** QueryResult accepts a query result in the form of an array of
    bytes read off the network (and a query) and parses the results
    and provides a number of utility routines to read the
    values back.

    @author Sam Madden (madden@cs.berkeley.edu)
*/
public class QueryResult {

    //we have to keep track of offsets into aggregate data by
    //hand, since we don't have a message class to represent them
    static final int GROUP_B1 = 1;  //start of aggregate data
    static final int GROUP_B2 = 0;
    static final int EXPR_IDX_B = 2;
    
	public static final int DATA_OFFSET = 3;
    

   /**
	* Constructor -- parse the specified result assuming it
	*is a result for query q
    */
    public QueryResult(TinyDBQuery q, QueryResultMsg m) {
		short curByte = 0;
		FieldRecord fr;
	
		myQuery = q;
		myEpoch = m.get_epoch();
		myQueryID = m.get_qid();
		isAggregateQuery = q.isAgg();
		fieldValues = new Vector();
		fieldValueObjs = new Vector();
		valid = new boolean[q.numExprs()];
		
		try {
			if (isAggregateQuery) {  //aggregate query
				int exprIndex = (int)m.getElement_d_data(EXPR_IDX_B);
				//get group number
				myGroup = ByteOps.makeInt(m.getElement_d_data(GROUP_B2),
							              m.getElement_d_data(GROUP_B1));
				
			    /* This result corresponds to just one of (possibly several)
				   aggregate expressions in the query.
				*/
				AggOp agg = ((AggExpr)myQuery.getExpr(exprIndex)).getAgg();
				//dont want users mess with the whole message
				//just give them their data
				byte[] resultData = new byte[m.get_d_data().length - DATA_OFFSET];
				System.arraycopy(m.get_d_data(),DATA_OFFSET,resultData,0,resultData.length);
				agg.read(resultData);
	
				/* include in the result vector (see resultVector() */
				valid[exprIndex] = true;
				
	    	} else {  //non aggregate query
				long nullFields = m.get_d_t_notNull();
				for (int i = 0; i < m.get_d_t_numFields(); i++) {
				    if ((nullFields & (1 << i)) > 0) {
					
					Vector fieldV = new Vector();
					fr = decodeField(i, m, curByte);
					fieldV.addElement(fr.name);
					if (fr.field instanceof byte[])
					    fieldV.addElement((byte[])fr.field);
					else
					    fieldV.addElement(fr.field.toString());
					fieldValues.addElement(fieldV);
					if (TinyDBMain.debug)
					    System.out.print(fieldV.elementAt(0) + " = " + fieldV.elementAt(1) + ", ");
					fieldValueObjs.addElement(fr.field);
					curByte += fr.size;
					
				    }
				    else
					{
					    Vector fieldV = new Vector();
					    QueryField f = myQuery.getField(i);
					    fieldV.addElement(f.getName());
					    fieldV.addElement(null);
					    fieldValues.addElement(fieldV);
					    fieldValueObjs.addElement(null);
					}
				}
		}
			if (TinyDBMain.debug) System.out.println(" ");
		} catch (ArrayIndexOutOfBoundsException e) {
		    System.out.println("Bad tuple.");
		}
		//if (TinyDBMain.isForGSK)
		//	convertGSKSensorValues();
    }

	public Object getFieldObj(String name)
	{
	    for (int i = 0; i < fieldValues.size(); i++) 
		{
			Vector v = (Vector)fieldValues.elementAt(i);
			String fieldName = (String)v.elementAt(0);
			if (fieldName.equalsIgnoreCase(name))
				return fieldValueObjs.elementAt(i);
		}
		return null;
	}

//  	private void convertGSKSensorValues()
//  	{
//  		Integer convVal;
//  	    for (int i = 0; i < fieldValues.size(); i++) 
//  		{
//  			Vector v = (Vector)fieldValues.elementAt(i);
//  			String fieldName = (String)v.elementAt(0);
//  			Object fieldObj = fieldValueObjs.elementAt(i);
//  			if (fieldObj == null)
//  				continue;
//  			if (fieldName.equalsIgnoreCase("hamatop") ||
//  				fieldName.equalsIgnoreCase("hamabot"))
//  			{
//  				Integer voltObj = (Integer)getFieldObj("voltage");
//  				int voltage = 204; // XXX about 2.9V
//  				if (voltObj != null)
//  					voltage = voltObj.intValue();
//  				int hama = (int)GDI2SoftConverter.hamamatsu(((Integer)fieldObj).intValue(), voltage);
//  				fieldValueObjs.setElementAt(new Integer(hama), i);
//  				v.setElementAt(String.valueOf(hama), 1);
//  			}
//  			else if (fieldName.equalsIgnoreCase("taostop") ||
//  					 fieldName.equalsIgnoreCase("taosbot"))
//  			{
//  				int taos = ((Integer)fieldObj).intValue();
//  				int ch0 = taos & 0xFF;
//  				int ch1 = (taos >> 8) & 0xFF;
//  				int photo = (int)GDI2SoftConverter.photo(ch0, ch1);
//  				fieldValueObjs.setElementAt(new Integer(photo), i);
//  				v.setElementAt(String.valueOf(photo), 1);
//  			}
//  			else if (fieldName.equalsIgnoreCase("humid"))
//  			{
//  				Integer tempObj = (Integer)getFieldObj("humtemp");
//  				int temp = 6000; // XXX about 20 C
//  				if (tempObj != null)
//  					temp = tempObj.intValue();
//  				int humidity = (int)GDI2SoftConverter.humid_adj(((Integer)fieldObj).intValue(), temp);
//  				Integer humObj = new Integer(humidity);
//  				fieldValueObjs.setElementAt(humObj, i);
//  				v.setElementAt(String.valueOf(humidity), 1);
//  			}
//  			else if (fieldName.equalsIgnoreCase("humtemp"))
//  			{
//  				int humtemp = (int)GDI2SoftConverter.humid_temp(((Integer)fieldObj).intValue());
//  				Integer tempObj = new Integer(humtemp);
//  				fieldValueObjs.setElementAt(tempObj, i);
//  				v.setElementAt(String.valueOf(humtemp), 1);
//  			}
//  			else if (fieldName.equalsIgnoreCase("press"))
//  			{
//  			}
//  			else if (fieldName.equalsIgnoreCase("prtemp"))
//  			{
//  			}
//  			else if (fieldName.equalsIgnoreCase("voltage"))
//  			{
//  				int voltage = (int)GDI2SoftConverter.voltage(((Integer)fieldObj).intValue());
//  				Integer voltObj = new Integer(voltage);
//  				fieldValueObjs.setElementAt(voltObj, i);
//  				v.setElementAt(String.valueOf(voltage), 1);
//  			}
//  			else if (fieldName.equalsIgnoreCase("thermo"))
//  			{
//  				int thermo = (int)GDI2SoftConverter.thermopile(((Integer)fieldObj).intValue());
//  				Integer thermoObj = new Integer(thermo);
//  				fieldValueObjs.setElementAt(thermoObj, i);
//  				v.setElementAt(String.valueOf(thermo), 1);
//  			}
//  			else if (fieldName.equalsIgnoreCase("thmtemp"))
//  			{
//  				int thmtemp = (int)GDI2SoftConverter.thermistor(((Integer)fieldObj).intValue());
//  				Integer tempObj = new Integer(thmtemp);
//  				fieldValueObjs.setElementAt(tempObj, i);
//  				v.setElementAt(String.valueOf(thmtemp), 1);
//  			}
//  	    }
//  	}

    /** Given a query result message, return the query id it belongs to */
    static public byte queryId(QueryResultMsg m) {
		return (byte)m.get_qid();
    }

    /** Return the epoch of this result */
    public int epochNo() {
		return myEpoch;
    }

    /** Return the query id of this result */
    public int qid() {
		return myQueryID;
    }

    /** Return the group number of this result */
    int group() {
		return myGroup;
    }

	public static int numFields(QueryResultMsg m) {
	    return m.get_d_t_numFields();
	}

    /**
	 * Merge the newResult with this query result.
	 * Merging combines information from several aggregate results
	 * that correspond the evaluations of different aggregate expressions
	 * over the tuple.
	 * NOTE: Merging values from the same aggregate expression reported to the root
	 *  by different sensors should be done on motes side
	 */
    public void mergeQueryResult(QueryResult newResult) {
		if (newResult.myGroup == myGroup) {
			for (int i = 0; i < myQuery.numExprs(); i++) {
				if (newResult.valid[i] && !valid[i]) { //new result has an expr we dont
					valid[i] = true;
					AggOp thisAgg = ((AggExpr)myQuery.getExpr(i)).getAgg();
					AggOp otherAgg = ((AggExpr)newResult.myQuery.getExpr(i)).getAgg();
					//copy state from the new result into this agg state
					otherAgg.copyResultState(thisAgg);
				} else if (newResult.valid[i] && valid[i]) {
					// do nothing, should be handled on motes side
					System.out.println("This should be done on mote side?");
				}
	    	}
		}
    }
  

   /**
	* Return a FieldRecord representing the value of the idxth column of the query, which is assumed
	*  to begin at offset bytes into result.
    */
    private FieldRecord decodeField(int idx, QueryResultMsg m, short offset) throws ArrayIndexOutOfBoundsException {
		TinyDBQuery q = myQuery;
	
		QueryField f = q.getField(idx);
		FieldRecord fr = new FieldRecord();
	
		fr.name = f.getName();
		switch (f.getType()) {
		case QueryField.UINTONE:
			fr.size = 1;
			fr.field = new Integer(ByteOps.unsign(m.getElement_d_t_fields(offset)));
			break;
		case QueryField.INTONE:
			fr.size = 1;
			fr.field = new Byte((byte)m.getElement_d_t_fields(offset));
			break;
		case QueryField.INTTWO:
		case QueryField.UINTTWO:
			int i = ByteOps.makeInt(m.getElement_d_t_fields(offset),
									m.getElement_d_t_fields(offset + 1));
			fr.size = 2;
			fr.field = new Integer(i);
			break;
		case QueryField.INTFOUR:
		case QueryField.UINTFOUR:
			long l = ByteOps.makeLong(m.getElement_d_t_fields(offset),
									  m.getElement_d_t_fields(offset + 1),
									  m.getElement_d_t_fields(offset + 2),
									  m.getElement_d_t_fields(offset + 3));
			fr.size = 4;
			fr.field = new Long(l);
			break;
		case QueryField.STRING:
			int len = 0;
			byte[] data = new byte[m.totalSize_d_data()];
			
			while (m.getElement_d_t_fields(offset + len) != 0) {
			data[len] = (byte)m.getElement_d_t_fields(offset + len);
			len++;
			}
			fr.size = 8;//hack! -- assume strings are always 8 bytes
			fr.field = new String(data,0,len);
			break;
		case QueryField.BYTES:
			{
				byte[] d = new byte[8];
				for (int k = 0; k < 8; k++)
				{
					d[k] = (byte)m.getElement_d_t_fields(offset + k);
				}
				fr.size = 8;
				fr.field = d;
			}
			break;
		default:
			System.out.println("UNSUPPORTED TYPE: " + f.getType());
		}
		return fr;

    }
  
    /**
	 * Return a vector of strings corresponding to the result tuple for this
	 * query result.
	 *
	 * Always includes epoch number as the first field.
	 *
	 * The names of the result fields can be obtained from
	 * TinyDBQuery.getColumnHeadings
	 *
     */
    public Vector resultVector() {
		Vector v = new Vector();
		int loc = 0;
	    // include epoch
		v.addElement(new Integer(myEpoch).toString());
	
		if (isAggregateQuery) {
			if (myQuery.grouped()) {
			  v.addElement(new Integer(myGroup).toString());
			  loc++;
			}
			for (int i = 0; i < myQuery.numExprs(); i++) {
				if (myQuery.getExpr(i).isAgg()) loc++;
				if (valid[i]) {
					AggOp agg = ((AggExpr)myQuery.getExpr(i)).getAgg();
					String aggStr = "";
				
					agg.finalizeValue();
					aggStr = agg.getValue();
					if (TinyDBMain.debug)
						System.out.println("aggregate result: epoch = " + myEpoch + "result = " + aggStr);
					
					if (v.size() <= loc) v.setSize(loc + 1);
					v.setElementAt(aggStr, loc);
				}
			}
		} else {
			for (int i = 0 ; i < fieldValues.size(); i++) {
				Vector vals = (Vector)fieldValues.elementAt(i);
				v.addElement(vals.elementAt(1));
			}
		}
		return v;
    }

    /** Convert this query result to an (ugly looking) string representation */
    public String toString() {
	String s = new String();
	if (isAggregateQuery) {
	    for (int i = 0; i < myQuery.numExprs(); i++) {
		if (valid[i])
		    s += "AGGREGATE VALUE: qid = " + myQueryID + ", epoch = " + myEpoch + ", expr = " + i + ", group = " + myGroup;
				// + ", value = " + value[i] + ", count = " + count[i];
	    }
	} else {

	    s += "TUPLE: qid = " + myQueryID + ", epoch = " + myEpoch + ", ";
	    for (int i = 0; i < fieldValues.size(); i++) {
		Vector v = (Vector)fieldValues.elementAt(i);
		s += (String)v.elementAt(0);
		s += " = ";
		if (v.elementAt(1) != null)
		    s += v.elementAt(1).toString();
		else
		    s += "null";
		s += ", ";
	    }
	}
	return s;
    }

	public Vector getFieldValueObjs()
	{
		return fieldValueObjs;
	}

	public TinyDBQuery getQuery()
	{
		return myQuery;
	}
	
    private boolean isAggregateQuery;  //is this an aggregate query
    private Vector fieldValues; //vector of field name / value string vectors (if a non-aggregata query)
	private Vector fieldValueObjs; // vector of field value objects, used for GSK only
	private Vector fieldNames;
	private Vector fieldTypes;

    //aggregate values
    private int myGroup; //the group this aggregate result belongs to (or 0 if not grouped)
    
	private boolean[] valid; /* Array of booleans indicating which exprs are
				valid aggregate expressions that are included in this result */

    private int mySenderID;  //sender id
    private int myParentID; //parent id
    private int myEpoch; //epoch number
    private int myQueryID; //query id

    private TinyDBQuery myQuery;
	
}

//internal class used to represent a tuple field
class FieldRecord {
    String name;
    int size;  // in bytes
    Object field;

}
