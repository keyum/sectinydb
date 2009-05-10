// $Id: WaveletReader.java,v 1.3 2003/10/07 21:46:07 idgay Exp $

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

import net.tinyos.tinydb.*;
import net.tinyos.util.ByteOps;

/**
 * Implements reader for Wavelet aggregate
 *
 * @author Joe Hellerstein
 * @version 1.0, December 23, 2002
 *
 */
public class WaveletReader implements AggregateResultsReader {
    /**
	 * Reads data from the byte array from QueryResultMessage
	 */
	static int NUMCOEF = 4;

    public void read(byte[] data) {
		myState = new WaveletData();
		int i;
	
		//		System.err.print("read wavelet: ");
		//for (i = 0; i < 25; i++)
		//System.err.println("data[" + i + "]: " + data[i]);
		myState.cnt = data[0];
		myState.doublings = data[1];
		//System.err.print("cnt (data[" + DATA_OFFSET + "])="+d.cnt+
		//			 ", doublings (data[" + (DATA_OFFSET+1) + "]) ="+d.doublings+" || ");
		for (i = 0; i < NUMCOEF; i++) {
			myState.offsets[i] = data[2+i];
			myState.data[i] = data[2+NUMCOEF+i];
			//System.err.print(d.offsets[i] + ", " + d.data[i] + " | ");
		}
		// System.err.println("|");
    }
	
	/**
	 * Calculates final value of the aggregate.
	 */
	public void finalizeValue() {
		//System.err.println("In Wavelet.finalizeValue");
	}
	
	/**
	 * Returns string representation of the finalized value
	 */
	public String getValue() {
	    
			int i, j, offset, sum=0;

			//System.err.println("In Wavelet.getValue: " + wd);
			StringBuffer buf = new StringBuffer();
			// eventually need to drop the right number of zero-pads.
			int limit = (int) (Math.pow(2,myState.doublings) ) * NUMCOEF;
			//System.err.println("limit = " + limit);

			buf.append("cnt " + myState.cnt + ", dblgs " + myState.doublings);
			buf.append(": [ ");

			if (myState.cnt <= 0) { // UNCOMPRESSED!  Hence dense.
			  for (i = 0; i < (-1)*myState.cnt; i++) {
				buf.append(myState.data[i]);
				if (i < ((-1)*myState.cnt) - 1)
				  buf.append(", ");
			  }
			}
			else { // COMPRESSED!  NEED TO UNCOMPRESS FIRST.
			  int half = limit/2;
			  short dcmp[] = new short[limit];

			  // For debugging purposes, print out in compressed format
			  // System.err.print("cnt " + wd.cnt + ", dblngs " + wd.doublings + ":");
			  System.err.print("< ");
			  for (i = 0, offset = 0; i < limit; i++) {
				  if (offset < NUMCOEF && i == myState.offsets[offset])
					  System.err.print(myState.data[offset++]);
				  else
					  System.err.print("x");
				  if (i < limit - 1)
					  System.err.print(", ");
			  }
			  System.err.println(" >");
				  
		     
			  // densify.
			  for (i = 0, j = 0; i < limit; i++) {
				if (j < NUMCOEF && myState.offsets[j] == i)
				  dcmp[i] = myState.data[j++];
				else dcmp[i] = 0;
			  }

			  // update
			  for (i = 0, j = half; i < half; i++, j++) {
				dcmp[i] = (short)(dcmp[i] - Math.floor(dcmp[j]/2));
			  }

			  // predict
			  for (i = half, j = 0; i < limit; i++, j++) {
				dcmp[i] = (short)(dcmp[i] + dcmp[j]);
			  }

			  //merge
			  int start = half-1;
			  int end = half;
			  short tmp;

			  while (start > 0) {
				for (i = start; i < end; i = i + 2) {
				  tmp = dcmp[i];
				  dcmp[i] = dcmp[i+1];
				  dcmp[i+1] = tmp;
				}
				start = start - 1;
				end = end + 1;
			  }

			  // print the sucker out
			  for (i = 0, j=limit-myState.cnt; i < limit; i++) {
				  // omit (limit-cnt) 0's if possible!
				  if (dcmp[i] == 0 && j > 0)
					  j--;
				  else {
					  buf.append(dcmp[i]);
					  sum += dcmp[i];
					  if (i < (limit -1))
						  buf.append(", ");
				  }
			  }
			  buf.append(" AVG: " + sum/myState.cnt);
			}

			buf.append(" ]");

			String retval = new String(buf);
			return retval;
	}
	
	public void copyResultState(AggregateResultsReader reader) {
		if (! (reader instanceof WaveletReader)) throw new IllegalArgumentException("Wrong type reader");
	
		WaveletReader wr = (WaveletReader)reader;
		wr.myState.cnt = myState.cnt;
		wr.myState.doublings = myState.doublings;
		System.arraycopy(myState.offsets,0,wr.myState.offsets,0,myState.offsets.length);
		System.arraycopy(myState.data,0,wr.myState.data,0,myState.data.length);
	}
	
	WaveletData myState;
}

class WaveletData {
    int cnt = 0;
    int doublings = 0;
    int offsets[] = {0, 0, 0, 0};
	short data[] = {0, 0, 0, 0};
}
