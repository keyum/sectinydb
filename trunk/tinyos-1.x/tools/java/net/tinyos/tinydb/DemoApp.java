// $Id: DemoApp.java,v 1.2 2003/10/07 21:46:07 idgay Exp $

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
import net.tinyos.tinydb.parser.*;
import java.util.Vector;
import java.io.*;

/** 
    Simple standalone demo application to run a 
    query and print out the results.  
*/

public class DemoApp implements ResultListener{
    public DemoApp() {
	try {
	    //initialize
	    TinyDBMain.initMain();
	
	    //parse the query
	    q = SensorQueryer.translateQuery("select light", (byte)1);
	    
	    //inject the query, registering ourselves as a listener for result
	    System.out.println("Sending query.");
	    TinyDBMain.injectQuery( q, this);

	} catch (IOException e) {
	    System.out.println("Network error.");
	} catch (ParseException e) {
	    System.out.println("Invalid Query.");
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
	new DemoApp();
    }
    
    TinyDBQuery q;
}
