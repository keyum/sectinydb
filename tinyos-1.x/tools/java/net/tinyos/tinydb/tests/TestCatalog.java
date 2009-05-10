// $Id: TestCatalog.java,v 1.3 2003/10/07 21:46:08 idgay Exp $

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
/**
 * TestDatabase.java
 *
 * @author Eugene Shvets 2/21/03
 */

/*
 * This class holds information about test queries read from an XML file.
 * Individual test cases can rely on this repository to choose test queries
 * with certain properties. For example, ParserTest uses TestDatabase to get
 * access to parsable and unparsable queries.
 * Testdatabase should be constructed by calling makeTestDatabase. Reference to
 * it can be obtained by calling getTestDatabase.
 */

package net.tinyos.tinydb.tests;

import java.io.*;
import java.util.*;
import java.text.ParseException;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.ParserAdapter;
import org.xml.sax.helpers.ParserFactory;
import org.xml.sax.helpers.XMLReaderFactory;


public class TestCatalog extends DefaultHandler {
	
	protected TestCatalog(String testFile) {
		
		myParsableTestQueries = new ArrayList();
		myUnParsableTestQueries = new ArrayList();
		
		try {
			XMLReader parser = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
			parser.setContentHandler(this);
			parser.parse(testFile);
		} catch (SAXParseException e) {
			System.out.println("Parse error occured!");
			e.printStackTrace();
			System.exit(1);
		} catch (SAXException e) {
			System.out.println("Parse error occured!");
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			System.out.print("Could not open catalog file:" + e.getMessage());
			e.printStackTrace();
			System.exit(1);
		}
	}
	
	public static void makeTestCatalog(String testFile) {
		ourTestCatalog = new TestCatalog(testFile);
	}
	
	public static TestCatalog getTestCatalog() { return ourTestCatalog; }
	
	public List getParsableQueries() { return myParsableTestQueries; }
	
	public List getUnparsableQueries() { return myUnParsableTestQueries; }
	
	
	/***************************************************************************
	 * SAX parsing
	 **************************************************************************/
	
	public void startElement(String uri, String localName, String qname,
							 Attributes attributes) throws SAXException {
		if (localName.equals("test")) {
			//set defaults
			query = null;
			fields = null;
			parsable = "false";
			epochsToRun = "1";
			results = null;
		} else if (localName.equals("query")) {
			query = "";
			parsingState = PARSING_QUERY;
		} else if (localName.equals("fields")) {
			parsingState = PARSING_FIELDS;
		} else if (localName.equals("parsable")) {
			parsable="";
			parsingState = PARSING_PARSABLE;
		} else if (localName.equals("epochsToRun")) {
			epochsToRun="";
			parsingState = PARSING_EPOCHS;
		} else if (localName.equals("tuple")) {
			tuple="";
			parsingState = PARSING_TUPLE;
		} else if (localName.equals("waitingTime")) {
			waitingTime = "";
			parsingState = PARSING_WAITING_TIME;
		} else if (localName.equals("results")) {
			results = new ArrayList();
			//by now epochsToRun should be determined
			int epochCount = Integer.valueOf(epochsToRun).shortValue();
			for(int i=0; i < epochCount; i++) {
				results.add(new ArrayList());
			}
		}
    }
	
	public void endElement(String uri, String localName, String qname) throws SAXException {
		if (localName.equals("test")) {
			if (Boolean.valueOf(parsable).booleanValue()) {
				TestQuery testQuery = new TestQuery(query,
													  	true,
													  	Integer.valueOf(epochsToRun).shortValue(),
														Integer.valueOf(waitingTime).intValue(),
													  	results);
				testQuery.setFieldList(fields);
				myParsableTestQueries.add(testQuery);
				
			} else {
				myUnParsableTestQueries.add(TestQuery.makeUnparsableQuery(query));
			}
			
			if (DEBUG) System.out.println("Created test query with results:" + results);
			
		} else if (localName.equals("tuple")) {
			addResultTuple(tuple);
		}
		
		parsingState = 0; //suffices for now, since we only have one section
    }
	
	/**
	 * Consume element data
	 */
    public void characters(char[] ch, int offset, int length) throws SAXException {
		String s = new String(ch, offset, length);
		
		switch(parsingState) {
			case PARSING_QUERY:
				query += s; break;
			case PARSING_FIELDS:
				fields += s; break;
			case PARSING_PARSABLE:
				parsable += s; break;
			case PARSING_EPOCHS:
				epochsToRun += s; break;
			case PARSING_TUPLE:
				tuple += s; break;
			case PARSING_WAITING_TIME:
				waitingTime += s; break;
		}
    }
	
	private void addResultTuple(String tuple) {
		//determine the epoch of the tuple
		int i=tuple.indexOf(" ");
		int epoch = Integer.parseInt(tuple.substring(0,i))-1;
		Vector readings = new Vector();
		StringTokenizer st = new StringTokenizer(tuple, " ");
		while(st.hasMoreTokens()) {
			readings.add(st.nextToken());
		}
		((ArrayList)results.get(epoch)).add(readings);
		
	}
	
	
	private static TestCatalog ourTestCatalog;
	
	private int myQueryWaitingTime;
	private List myParsableTestQueries; //ArrasyList<TestQuery>
	private List myUnParsableTestQueries; //ArrasyList<TestQuery>
	
	
	//parsing state
	private String query;
	private String fields;
	private String parsable;
	private String epochsToRun;
	private String waitingTime;
	private String tuple;
	private ArrayList results;//ArrayList<ArrayList<Vector>>,
	//where myResults[i] is the list of results for epoch i+1
	
	private int parsingState;
	
	private static final int PARSING_QUERY =    0x1;
	private static final int PARSING_FIELDS =   0x2;
	private static final int PARSING_PARSABLE = 0x4;
	private static final int PARSING_EPOCHS =   0x8;
	private static final int PARSING_TUPLE =  0x10;
	private static final int PARSING_WAITING_TIME = 0x20;
	
	
	private static final boolean DEBUG = true;
	
}

