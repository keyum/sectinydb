// $Id: main.java,v 1.2 2003/10/07 21:46:08 idgay Exp $

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

import java_cup.runtime.Symbol;
import java.io.*;
import net.tinyos.tinydb.*;

public class main {

  static boolean run_query = true;

  static public void main(String[] args) throws java.io.IOException {

      //String query = "select avg(sensors.temp) cnt(sensors.temp) from sensors where sensors.light > 20 and sensors.temp < 58 group by sensors.light >> 2 epoch duration 128";
      //String query = "select avg(s.light) from sensors as s where sensors.light < 20 group by sensors.temp >> 2 epoch duration 1024";
      String query = "select avg(light/10) where temp > 200 group by temp";

      System.out.println("Translating query: "+ query);
      Catalog.curCatalog = new Catalog("catalog");
      TinyDBQuery tdb_query = null;
      try {
	  tdb_query = SensorQueryer.translateQuery(query, (byte) 1);
      } catch (ParseException pe) {
	    System.err.println(pe.getMessage());
	    pe.printStackTrace();
	    System.err.println(pe.getParseError());
	    return;
      }

      System.out.println(tdb_query);

//        if (run_query) {
//  	  AMInterface aif;
//  	  TinyDBNetwork nw;
	  
//  	  //open radio comm
//  	  try {
//  	      aif = new AMInterface("COM1", false);
//  	      aif.open();
	      
	      
//  	      for (int i = 0; i < 3; i++) {
//  		  aif.sendAM(CommandMsgs.resetCmd((short)-1), CommandMsgs.CMD_MSG_TYPE, (short)-1);
//  		  Thread.currentThread().sleep(200);
//  	      }
	      
//  	      nw = new TinyDBNetwork(aif);
//  	      nw.sendQuery(tdb_query);
//  	  } catch (Exception e) {
//  	      System.out.println("Open failed -- network won't work:" +e);
//  	      e.printStackTrace();
//  	  }
//        }
  }
} 

