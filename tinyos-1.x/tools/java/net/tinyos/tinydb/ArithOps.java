// $Id: ArithOps.java,v 1.2 2003/10/07 21:46:07 idgay Exp $

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

public class ArithOps {
    static final short NO_OP = 0;
    static final short MULTIPLY = 1;
    static final short DIVIDE = 2;
    static final short ADD = 3 ;
    static final short SUBTRACT = 4;
    static final short MOD = 5;
    static final short SHIFT_RIGHT = 6;

    static short getOp(String opStr) {
	if (opStr.equals("*"))
	    return MULTIPLY;
	else if (opStr.equals("/"))
	    return DIVIDE;
	else if (opStr.equals("+"))
	    return ADD;
	else if (opStr.equals("-"))
	    return SUBTRACT;
	else if (opStr.equals("%"))
	    return MOD;
	else if (opStr.equals(">>"))
	    return SHIFT_RIGHT;
	else return NO_OP;
    }

    static String getStringValue(short op) {
	switch (op) {
	case NO_OP:
	    break;
	case MULTIPLY:
	    return "*";
	case DIVIDE:
	    return "/";
	case ADD:
	    return "+";
	case SUBTRACT:
	    return "-";
	case MOD:
	    return "%";
	case SHIFT_RIGHT:
	    return ">>";
	}
	return "";
    }
}
    
