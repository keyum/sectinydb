// $Id: Catalog.java,v 1.23 2003/10/07 21:46:07 idgay Exp $

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

import java.io.*;
import java.util.*;
import java.text.ParseException;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.ParserAdapter;
import org.xml.sax.helpers.ParserFactory;
import org.xml.sax.helpers.XMLReaderFactory;

/**
 * Catalog manages a list of attributes and aggregates that are available to
 * TinyDB queries.  Currently this class just reads data from
 * a XML file, but future versions should support dynamically
 * building attribute lists from nearby motes.
 *
 * @author Sam Madden
 * Modifed by Eugene Shvets
 */
public class Catalog extends DefaultHandler {
	
	//static final String DEFAULT_VALIDATOR_CLASS = "net.tinyos.tinydb.DefaultArgumentValidator";
	//static final String DEFAULT_READER_CLASS = "net.tinyos.tinydb.IntReader";
	
    /** Constructor : create an empty catalog */
    public Catalog() {
	    attributes = new ArrayList();
	    fileName = null;
	    listeners = new ArrayList();
		predefinedQueries = new ArrayList();
	    //resultTypes = new HashMap();
	    aggregateCatalog = new AggregateCatalog();
    }
	
    /** Read a catalog from the specified file */
    public Catalog(String catalogFile) {
	    this();
	    fileName = catalogFile;
	    
	    System.out.println("Catalog file in use: " + catalogFile);
	    
	    try {
			XMLReader parser = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
			parser.setContentHandler(this);
			parser.parse(fileName);
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
    
    public void startElement(String uri, String localName, String qname,
							 Attributes attributes) throws SAXException {
		if (localName.equals("attributes")) {
			parsingState = PARSING_ATTRIBUTES;
		} else if (localName.equals("attribute")) {
		    min = 0;
		    max = 1000;
		} else if (localName.equals("aggregates")) {
			parsingState = PARSING_AGGREGATES;
		} else if (localName.equals("predefinedQueries")) {
			parsingState = PARSING_PREDEFQUERIES;
		} else if (localName.equals("aggregate")) { //set defaults for each aggregate
			curArgCount = "0";
			curValidator = defaultValidator;
			curReader = defaultReader;
		} if (localName.equals("type")) {
			parsingState |= PARSING_TYPE;
			curType = "";
		} else if (localName.equals("defaultReaderClass")) {
			parsingState |= PARSING_DEFAULT_READER;
			defaultReader = "";
		} else if (localName.equals("defaultValidatorClass")) {
			parsingState |= PARSING_DEFAULT_VALIDATOR;
			defaultValidator = "";
		} else if(localName.equals("name")) {
			parsingState |= PARSING_NAME;
			curName = "";
		} else if (localName.equals("minVal")) {
		    parsingState |= PARSING_MIN_VAL;
		    curVal = "";
		} else if (localName.equals("maxVal")) {
		    parsingState |= PARSING_MAX_VAL;
		    curVal = "";
		} else if(localName.equals("readerClass")) {
			parsingState |= PARSING_READER;
			curReader = "";
		} else if(localName.equals("validatorClass")) {
			parsingState |= PARSING_VALIDATOR;
			curValidator = "";
		} else if(localName.equals("id")) {
			parsingState |= PARSING_ID;
			curID = "";
		} else if(localName.equals("temporal")) {
			parsingState |= PARSING_TEMPORAL;
			curTemporal = "";
		} else if (localName.equals("argcount")) {
			parsingState |= PARSING_ARGCOUNT;
			curArgCount = "";
		} else if (localName.equals("query")) {
			parsingState |= PARSING_QUERY;
			curPredefQuery = "";
		}
    }
    
    public void endElement(String uri, String localName, String qname) throws SAXException {
		if (localName.equals("attributes")) {
			parsingState = 0;
		} else if (localName.equals("aggregates")) {
			parsingState = 0;
		} else if (localName.equals("predefinedQueries")) {
			parsingState = 0;
		} if (localName.equals("type")) {
			parsingState &= ~PARSING_TYPE;
		} else if(localName.equals("name")) {
			parsingState &= ~PARSING_NAME;
		} else if(localName.equals("defaultReaderClass")) {
			parsingState &= ~PARSING_DEFAULT_READER;
		} else if(localName.equals("defaultValidatorClass")) {
			parsingState &= ~PARSING_DEFAULT_VALIDATOR;
		} else if(localName.equals("readerClass")) {
			parsingState &= ~PARSING_READER;
		} else if(localName.equals("validatorClass")) {
			parsingState &= ~PARSING_VALIDATOR;
		} else if(localName.equals("id")) {
			parsingState &= ~PARSING_ID;
		} else if(localName.equals("temporal")) {
			parsingState &= ~PARSING_TEMPORAL;
		} else if (localName.equals("argcount")) {
			parsingState &= ~PARSING_ARGCOUNT;
		} else if (localName.equals("query")) {
			parsingState &= ~PARSING_QUERY;
			predefinedQueries.add(curPredefQuery);
		} else if (localName.equals("minVal")) {
		    parsingState &= ~PARSING_MIN_VAL;
		    try {
			min = new Integer(curVal).intValue();
		    } catch (NumberFormatException e) {
			throw new SAXException("Invalid minimum value : " + curVal);
		    }
		} else if (localName.equals("maxVal")) {
		    parsingState &= ~PARSING_MAX_VAL;
		    try {
			max = new Integer(curVal).intValue();
		    } catch (NumberFormatException e) {
			throw new SAXException("Invalid maximum value : " + curVal);
		    }

		} else if (localName.equals("attribute")) {
			try {

				addAttr(new QueryField(curName, stringToType(curType), min, max));
			} catch (ParseException e) {
				throw new SAXException(e.getMessage());
			}
		} else if (localName.equals("aggregate")) {
			try {
				if (DEBUG) {
					System.out.println("id: " + curID);
					System.out.println("name: " + curName);
					System.out.println("temporal: " + curTemporal);
					System.out.println("argcount: " + curArgCount);
					System.out.println("reader: " + curReader);
					System.out.println("validator: " + curValidator);
				}
				aggregateCatalog.registerAggregate(Integer.valueOf(curID).intValue(),
												curName,
												Boolean.valueOf(curTemporal).booleanValue(),
												Integer.valueOf(curArgCount).intValue(),
												curReader,
											   	curValidator);
			} catch (InvalidAggregateDefinitionException e) {
				e.printStackTrace();
				throw new SAXException(e.getMessage());
			}
		}
		
    }
    
    /**
	 * Consume element data
	 */
    public void characters(char[] ch, int offset, int length) throws SAXException {
		String s = new String(ch, offset, length);
		//ATTRIBUTES
		if ((parsingState & PARSING_ATTRIBUTES) != 0) {
			if ((parsingState & PARSING_NAME) != 0) {
				curName += s;
			} else if ((parsingState & PARSING_TYPE) != 0) {
				curType += s;
			} else if ((parsingState & (PARSING_MIN_VAL | PARSING_MAX_VAL)) != 0){
			    curVal += s;
			} 
			return;
		}
		// AGGREGATES
		if ((parsingState & PARSING_AGGREGATES) != 0) {          // name
			if ((parsingState & PARSING_NAME) != 0) {
				curName += s;
			} else if ((parsingState & PARSING_ID) != 0) {       // id
				curID += s;
			} else if ((parsingState & PARSING_TEMPORAL) != 0) { // temporal
				curTemporal += s;
			} else if ((parsingState & PARSING_ARGCOUNT) != 0) { // argcount
				curArgCount += s;
			} else if ((parsingState & PARSING_VALIDATOR) != 0) {// validator
				curValidator += s;
			} else if ((parsingState & PARSING_READER) != 0) {   // reader
				curReader += s;
			} else if ((parsingState & PARSING_DEFAULT_READER) != 0) {
				defaultReader += s;
			} else if ((parsingState & PARSING_DEFAULT_VALIDATOR) != 0) {
				defaultValidator += s;
			}
			return;
		}
		
		//PREDEFINED QUERIES
		if ((parsingState & PARSING_PREDEFQUERIES) != 0) {
			if ((parsingState & PARSING_QUERY) != 0) {
				curPredefQuery += s;
			}
			return;
		}
    }
    
    /**
	 * Returns current system catalog
	 */
    public static Catalog currentCatalog() { return curCatalog; }
    
    public AggregateCatalog getAggregateCatalog() { return aggregateCatalog; }
    
    /**
	 * Returns set of AggregateDescriptor.AggregateEntry objects registered with this catalog
	 */
    public Collection getAggregates() {
		return aggregateCatalog.getAggregates();
    }
	
	public Collection getPredefinedQueries() {
		return predefinedQueries;
	}
		
    public int numAttrs() {
	    return attributes.size();
    }
	
    public QueryField getAttr(int idx) {
		return (QueryField)attributes.get(idx);
    }
	
    public QueryField getAttr(String name) {
		Iterator it = attributes.iterator();
		while (it.hasNext()) {
			QueryField qf = (QueryField)it.next();
			if (qf.getName().equalsIgnoreCase(name)) return qf;
		}
		return null;
    }
	
    public void addAttr(QueryField f, boolean log) {
	    attributes.add(f);
	    if (fileName != null && log) {
			try {
				FileWriter fw = new FileWriter(fileName, true);
				
				fw.write(f.getName() + "\n");
				fw.close();
			} catch (IOException e) {
			}
	    }
	    Iterator it = listeners.iterator();
	    while (it.hasNext()) {
			CatalogListener cl = (CatalogListener)it.next();
			cl.addedAttr(f);
	    }
    }
	
    public void addAttr(QueryField f) {
		addAttr(f,false);
    }
	
	
    public void addListener(CatalogListener cl) {
		listeners.add(cl);
    }
    
    private static byte[] fieldBytes = {QueryField.INTONE, QueryField.UINTONE, QueryField.INTTWO, QueryField.UINTTWO,
			QueryField.INTFOUR, QueryField.UINTFOUR, QueryField.TIMESTAMP, QueryField.STRING, QueryField.BYTES};
    private static String[] fieldNames = {"int8", "uint8", "int16", "uint16", "int32", "uint32", "timestamp", "string", "bytes"};
	
	
    public static byte stringToType(String s) throws ParseException{
	    String l = s.toLowerCase();
	    for (int i = 0; i < fieldNames.length; i++) {
			if (l.equals(fieldNames[i])) return fieldBytes[i];
	    }
	    throw new ParseException("Unknown type: " + s, 0);
    }
	
    public static int numTypes() {
		return fieldBytes.length;
    }
	
    public static byte getTypeId(int idx) {
		return fieldBytes[idx];
    }
	
    public static String getTypeName(int idx) {
		return fieldNames[idx];
    }
 
	
	// state of XML parsing
    private int parsingState = 0;
    
    // tags
    private static final int PARSING_NAME        = 0x1;
    private static final int PARSING_TYPE        = 0x2;
	private static final int PARSING_DEFAULT_READER = 0x4;
	private static final int PARSING_DEFAULT_VALIDATOR = 0x8;
    private static final int PARSING_READER      = 0x10;
	private static final int PARSING_VALIDATOR   = 0x20;
    private static final int PARSING_ID          = 0x40;
    private static final int PARSING_TEMPORAL    = 0x80;
	private static final int PARSING_ARGCOUNT    = 0x100;
	private static final int PARSING_QUERY       = 0x200;
private static final int PARSING_MIN_VAL = 0x400;
private static final int PARSING_MAX_VAL = 0x800;

    // sections
    private static final int PARSING_ATTRIBUTES    = 0x2000;
    private static final int PARSING_AGGREGATES    = 0x4000;
	private static final int PARSING_PREDEFQUERIES = 0x8000;
    
    private int min, max;
    private String curName;
    private String curType;
    private String curReader;
	private String curValidator;
	private String defaultReader, defaultValidator;
    private String curID;
	private String curArgCount;//default 0
    private String curTemporal;
    private String curVal;
	//private boolean curWindowing;
	private String curPredefQuery;
	// end state of XML parsing
	
	
    private ArrayList attributes, predefinedQueries;
   
    private AggregateCatalog aggregateCatalog;
    
    private ArrayList listeners;
    
	/** A static variable containing the current (global) catalog */
    public static Catalog curCatalog;
	
    private String fileName;
    
    private static final boolean DEBUG = false;
	
}
