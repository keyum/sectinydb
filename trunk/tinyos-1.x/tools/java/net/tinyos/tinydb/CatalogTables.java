// $Id: CatalogTables.java,v 1.4 2003/10/07 21:46:07 idgay Exp $

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

public class CatalogTables {
    static final String ATTR_TABLE_NAME = "attributes";
    static final String COMMAND_TABLE_NAME = "commands";
    static final String EVENT_TABLE_NAME = "events";
    static final String QUERY_TABLE_NAME = "queries";
    static final QueryField[] ATTR_FIELDS = {new QueryField("name", QueryField.STRING)};
    static Vector CATALOG;
    public static final byte USER_DEFINED_TABLE_ID = -1;
    static {
	CATALOG = new Vector();
	CATALOG.addElement(new CatalogTableInfo(ATTR_TABLE_NAME, TinyDBQuery.ATTRLIST, ATTR_FIELDS));
    }

    
    public static int getTableIdFromName(String name) throws NoSuchElementException {
	for (int i = 0; i < CATALOG.size(); i++) {
	    CatalogTableInfo inf = (CatalogTableInfo)CATALOG.elementAt(i);
	    if (inf.name.equals(name))
		return inf.id;
	}
	throw (new NoSuchElementException());
    }

    public static boolean catalogTableHasField(String table, String field) {
	return getTableFieldInfo(table,field) != null;
    }

    public static QueryField getTableFieldInfo(String table, String field) {
	for (int i = 0; i < CATALOG.size(); i++) {
	    CatalogTableInfo inf = (CatalogTableInfo)CATALOG.elementAt(i);
	    System.out.println("comparing " + table + " to " + inf.name);
	    if (inf.name.equals(table)) {
		System.out.println("got match, num fields = " + inf.fields.length);
		for (int j = 0; j < inf.fields.length;j++) {
		    if (inf.fields[j] == null) {
			System.out.println("field is NULL!");
		    } else {
			System.out.println("FIELD: comparing " + field + " to " + inf.fields[j].getName());
			if (inf.fields[j].getName().equals(field))
			    return inf.fields[j];
		    }
		}
	    }
	}
	return null;
    }

    public static void addCatalogTable(String name, Vector fields) {
	QueryField[] fieldArray = new QueryField[fields.size()];
	System.out.println("adding table " + name + " with " + fields.size() + " fields.");
	for (int i = 0; i < fields.size(); i++) {
	    System.out.println("added table with field : " + fields.elementAt(i));
	    fieldArray[i] = (QueryField)fields.elementAt(i);
	}
	CATALOG.addElement(new CatalogTableInfo(name, USER_DEFINED_TABLE_ID, fieldArray));
	
    }
}

class CatalogTableInfo {
    public final String name;
    public final byte id;
    public final QueryField[] fields;
    public CatalogTableInfo(String name,byte id,QueryField[] fields) {
	this.name = name;
	this.id = id;
	this.fields=fields;
    }
}
