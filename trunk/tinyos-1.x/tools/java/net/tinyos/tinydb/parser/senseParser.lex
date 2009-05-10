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

//import sym.*;
import java_cup.runtime.*;

/* semantic value of token returned by scanner */
class TokenValue {
  public int lineBegin;
  public int charBegin;
  public String text;
  public String filename;
  
  TokenValue() {
  }
  
  TokenValue(String text, int lineBegin, int charBegin, String filename) {
    this.text = text;
    this.lineBegin = lineBegin;
    this.charBegin = charBegin;
    this.filename = filename;
  }

  public String toString() {
    return text;
  }

  public boolean toBoolean() {
    return Boolean.valueOf(text).booleanValue();
  }
  
  public int toInt() {
    return Integer.valueOf(text).intValue();
  }
}

%%

%implements java_cup.runtime.Scanner
%function next_token
%type java_cup.runtime.Symbol

%eofval{
  return new Symbol(sym.EOF, null);
%eofval}

%{
  public String sourceFilename;
%}

%line
%char
%state COMMENTS

ALPHA=[A-Za-z_]
DIGIT=[0-9]
ALPHA_NUMERIC={ALPHA}|{DIGIT}
IDENT={ALPHA}({ALPHA_NUMERIC})*
NUMBER=({DIGIT})+
WHITE_SPACE=([\ \n\r\t\f])+

WHERE="WHERE"|"where"
FROM="FROM"|"from"
QUERY_STRING="QUERY"|"query"
AND="AND"|"and"
SELECT="SELECT"|"select"
LESS_EQUAL="<="
OR="OR"|"or"
RPAREN=")"
EQUAL="="
COLON=":"
GREATER_THAN=">"
GROUP_BY="GROUP BY"|"group by"
EPOCH="EPOCH"|"epoch"|"SAMPLE"|"sample"
DURATION="DURATION"|"duration"|"period"|"PERIOD"
ONE_SHOT="ONCE"|"once"
DROPALL="DROP ALL" | "drop all"
FOR="FOR"|"for"
AS="AS"|"as"
SUM="SUM"|"sum"
PERIOD="."
COMMA=","
NOT_EQUAL="<>"
GREATER_EQUAL=">="
LPAREN="("
LESS_THAN="<"
AVG="AVG"|"avg"|"AVERAGE"|"average"
MIN="MIN"|"min"|"MINIMUM"|"minimum"
MIN3="MIN3"|"min3"
CNT="CNT"|"cnt"|"COUNT"|"count"
MAX="MAX"|"max"|"MAXIMUM"|"maximum"
EXPAVG="EXPAVG"|"expavg"
WINAVG="WINAVG"|"winavg"
WINMIN="WINMIN"|"winmin"
WINMAX="WINMAX"|"winmax"
WINSUM="WINSUM"|"winsum"
WINCNT="WINCNT"|"wincnt"
NOOP="NOOP"|"noop"
WINRAND="WINRAND"|"winrand"
DELTA="DELTA"|"delta"
ADPDELTA="ADPDELTA"|"adpdelta"
TREND="TREND"|"trend"
ACTION="OUTPUT ACTION"|"output action"|"TRIGGER ACTION"|"trigger action"
BUFFER="BUFFER"|"buffer"
ONEVENT="ON EVENT"|"on event"
CREATE="CREATE BUFFER"|"create buffer"
SIZE="SIZE"|"size"
INTO="INTO"|"into"
ARITHMETIC_OP="+"|"-"|"*"|"/"|"%"|">>"
NAME={IDENT}
CONSTANT={NUMBER}


%%


<YYINITIAL> {WHERE} {
  return new Symbol(sym.WHERE, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {FROM} {
  return new Symbol(sym.FROM, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {QUERY_STRING} {
  return new Symbol(sym.QUERY_STRING, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {AND} {
  return new Symbol(sym.AND, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {SELECT} {
  return new Symbol(sym.SELECT, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {LESS_EQUAL} {
  return new Symbol(sym.LESS_EQUAL, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {OR} {
  return new Symbol(sym.OR, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {RPAREN} {
  return new Symbol(sym.RPAREN, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {EQUAL} {
  return new Symbol(sym.EQUAL, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {GREATER_THAN} {
  return new Symbol(sym.GREATER_THAN, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {CONSTANT} {
  return new Symbol(sym.CONSTANT, new Integer(Integer.parseInt(yytext())));
  //new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {GROUP_BY} {
  return new Symbol(sym.GROUP_BY, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}


<YYINITIAL> {PERIOD} {
  return new Symbol(sym.PERIOD, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {COMMA} {
  return new Symbol(sym.COMMA, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {COLON} {
  return new Symbol(sym.COLON, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}


<YYINITIAL> {NOT_EQUAL} {
  return new Symbol(sym.NOT_EQUAL, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {GREATER_EQUAL} {
  return new Symbol(sym.GREATER_EQUAL, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {LPAREN} {
  return new Symbol(sym.LPAREN, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {LESS_THAN} {
  return new Symbol(sym.LESS_THAN, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {ARITHMETIC_OP} {
  return new Symbol(sym.ARITHMETIC_OP, new String(yytext()));
}

<YYINITIAL> {EPOCH} {
  return new Symbol(sym.EPOCH, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {DURATION} {
  return new Symbol(sym.DURATION, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}


<YYINITIAL> {ONE_SHOT} {
  return new Symbol(sym.ONE_SHOT, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {DROPALL} {
  return new Symbol(sym.DROPALL, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {FOR} {
  return new Symbol(sym.FOR, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {ACTION} {
  return new Symbol(sym.ACTION, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {BUFFER} {
  return new Symbol(sym.BUFFER, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {ONEVENT} {
  return new Symbol(sym.ONEVENT, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {CREATE} {
  return new Symbol(sym.CREATE, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {SIZE} {
  return new Symbol(sym.SIZE, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {INTO} {
  return new Symbol(sym.INTO, new TokenValue(yytext(), yyline, yychar, sourceFilename));
}

<YYINITIAL> {AS} {
  return new Symbol(sym.AS, new String(yytext()));
}

<YYINITIAL> {NAME} {
  return new Symbol(sym.NAME, new String(yytext()));
}

<YYINITIAL> {WHITE_SPACE} { }

<YYINITIAL> "//" {
  yybegin(COMMENTS);
}
<COMMENTS> [^\n] {
}
<COMMENTS> [\n] {
  yybegin(YYINITIAL);
}

<YYINITIAL> . {
  return new Symbol(sym.error, null);
}

