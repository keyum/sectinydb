# Note that Yylex has to be made before QueryParser

all: senseParser.class sym.class Yylex.class main.class SensorQueryer.class

senseParser.java: senseParser.cup
	java java_cup.Main -parser senseParser < senseParser.cup

senseParser.class: senseParser.java Yylex.class
	javac senseParser.java

senseParser.lex.java: senseParser.lex
	java JLex.Main senseParser.lex

Yylex.java: senseParser.lex.java
	cp senseParser.lex.java Yylex.java

Yylex.class: Yylex.java
	javac Yylex.java

sym.class: sym.java
	javac sym.java

main.class: main.java
	javac main.java

ParseException.class: ParseException.java
	javac ParseException.java

SensorQueryer.class: SensorQueryer.java ParseException.class
	javac SensorQueryer.java

run:
	java net.tinyos.tinydb.parser.main

clean: 
	rm -f *.class Yylex.java senseParser.java sym.java *~ senseParser.lex.java
