/* QueryResultForwarder dumps messages received from a TOSBase into
   a TASK/TinyDB database.
*/
package net.tinyos.tinydb;

public class QueryResultForwarder implements ResultListener{
    static DBLogger db;

    public static void main(String argv[]) {
	if (argv.length != 3) {
	    System.out.println("USAGE: QueryResultForwarder query qid tableName");
	}
	int qid = new Integer(argv[1]).intValue();
	String queryString = argv[0];
	
	try {
	    TinyDBMain.initMain();
	    TinyDBMain.network.setPromiscuous(true);
	    TinyDBMain.debug = true;
	    TinyDBQuery q =  net.tinyos.tinydb.parser.SensorQueryer.translateQuery(queryString, (byte)qid);
	    TinyDBMain.notifyAddedQuery(q);
	    db = new DBLogger();
	    db.setupLoggingInfo(q, TinyDBMain.network, argv[2]);
	    db.setDupElim(true);	
	    TinyDBMain.network.addResultListener(new QueryResultForwarder(), true, qid);    
	} catch (java.sql.SQLException e) {
	    System.out.println("SQL Exception : " + e);
	} catch (net.tinyos.tinydb.parser.ParseException e) {
	    System.out.println("Invalid query : " + queryString + "\n" + e);
	} catch (java.io.IOException e) {
	    System.out.println("Network failed : " + e);
	}
    }

    public void addResult(QueryResult qr) {
	System.out.println("in add result.");
    }
}
