// $Id: Config.java,v 1.4 2003/10/07 21:46:07 idgay Exp $

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

public class Config {
    // lines in 
    public static void init(String configFile) {
	try {
	    BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(configFile)));
	    String line;
	    String param, value;
	    short lineno = 0;

	    while ((line = br.readLine()) != null) {
		line = line.trim();
		lineno++;
		if (line.length() > 0 && line.charAt(0) != '%') {
		    StringTokenizer st = new StringTokenizer(line, ":");
		    try {
			param = st.nextToken().trim();
			value = st.nextToken().trim();
			value = value.replace('$',':');
			opts.put(param, value);
			if (TinyDBMain.debug) System.out.println("param " + param + " set to " + value);
		    } catch (NoSuchElementException e) {
			System.out.println("Invalid config file entry, line " + lineno + ": " + line);
		    }
		}
	    }
	    
	} catch (IOException e) {
	    System.out.println("Config file error : " + e);
	}
    }
    
    public static String getParam(String param) {
	return (String)opts.get(param);
    }

    public static void setParam(String param, String value) {
	opts.put(param,value);
    }

    static Hashtable opts = new Hashtable();
}
