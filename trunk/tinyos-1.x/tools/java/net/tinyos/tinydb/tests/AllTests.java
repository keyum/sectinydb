// $Id: AllTests.java,v 1.6 2003/10/07 21:46:08 idgay Exp $

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
 * AllTests.java
 *
 * @author Eugene Shvets 1/29/03
 */

package net.tinyos.tinydb.tests;

import net.tinyos.tinydb.*;

import junit.framework.*;
import java.util.*;
import java.io.IOException;

public class AllTests {

	public static void main (String[] args) {
		//handle command line args
		if (args.length > 1) {
			printUsage();
			System.exit(1);
		}
		
		if (args.length == 1) {
			if (args[0].equals("-?")) {
				printUsage();
				System.exit(1);
			} else if (args[0].equals("-sim")) {
				TinyDBMain.simulate = true;
			}
		}
		
		//initialize DB
		try {
			TinyDBMain.initMain();
		} catch (IOException e) {
			System.out.println("TinyDBMain.initMain failed.");
			System.exit(1);
		}
		
		TestCatalog.makeTestCatalog("net/tinyos/tinydb/tests/tests.xml");
		junit.textui.TestRunner.run (suite());
	}
	
	public static Test suite ( ) {
		TestSuite suite= new TestSuite("All TinyDB Tests");
		suite.addTest(ParserTester.suite());
		
		//add all individual query tests
		List queries =  TestCatalog.getTestCatalog().getParsableQueries();
		for(Iterator it = queries.iterator(); it.hasNext(); ) {
			//dont reset the network before each query is executed
			suite.addTest(new QueryTester((TestQuery)it.next(), false));
		}
		
	    return suite;
	}
	
	private static void printUsage() {
		System.out.println("AllTests -sim | -?");
		System.out.println("-? prints this message");
		System.out.println("-sim run tests in the TinyDB simulator");
		
	}
	
}

