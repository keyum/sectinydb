// $Id: PersistentQueryDemo.java,v 1.3 2003/10/07 21:46:07 idgay Exp $

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
import net.tinyos.tinydb.parser.*;
import java.util.*;
import java.io.*;

public class PersistentQueryDemo implements ResultListener{
    TinyDBQuery q;
    String name;

    public PersistentQueryDemo(String queryStr, String persistentName) {
	try {
	    TinyDBMain.initMain();

	    this.name = persistentName;
	    
	    Runtime.getRuntime().addShutdownHook(new Thread() {
		    public void run() {
			System.out.println("Saving query state...");
			if (q.saveQuery(name, TinyDBMain.network))
			    System.out.println("SUCCESS!");
			else
			    System.out.println("FAIL!");
			
		    }
		});;
	    
	    q = TinyDBQuery.restore(persistentName, TinyDBMain.network);
	    if (q == null) {
		q = SensorQueryer.translateQuery(queryStr, (byte)1);
		DBLogger logger = new DBLogger(q, q.getSQL(), TinyDBMain.network);
		TinyDBMain.injectQuery(q, this);
	    } else
		TinyDBMain.network.addResultListener(this, true, q.getId());
	} catch (IOException e) {
	} catch (SQLException sqlex) {
	} catch (ParseException parseex) {
	}
    }


    /* ResultListenr method called whenever a result arrives */
    public void addResult(QueryResult qr) {
	Vector v = qr.resultVector();

	//print the result
	for (int i = 0; i < v.size(); i++) {
	    System.out.print("\t" + v.elementAt(i) + "\t|");
	}
	System.out.println();

    }

    public static void main(String argv[]) {
	if (argv.length != 2)
	    System.out.println("Invalid number of parameters.  \n Usage: ... query queryname]");
	new PersistentQueryDemo(argv[0], argv[1]);
    }

}

