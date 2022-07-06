package logtest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;



public class logtest {
	private static int count = 0;

	//tshark -r /data/pcap/scada.pcapng -T ek | jq '.' | java -jar log-generator-0.0.2.jar
	
    public static void main(String[] args) throws InterruptedException, IOException {
 
    	
    	

    	

            //String cmd = "tshark -r /data/pcap/scada.pcapng -T ek | jq '.'";
//            String cmd = "C:\\Program Files\\Wireshark\\tshark.exe -r C:\\Users\\65935\\Downloads\\docker-elk-main\\tshark\\logtest\\log\\scada.pcapng -T ek "     ;    
//            Process p = Runtime.getRuntime().exec(cmd);
//            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
    	
//           
    		String elasticip = args[0];  
    		String target = args[1];  

            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
          	StringBuilder everything = new StringBuilder();
     	    String lineeach;
     	    while( (lineeach = in.readLine()) != null) {
     	       everything.append(lineeach);
     	    }
     	    System.out.print("---------everything-----------");

     	    String every= everything.toString();
     	    
     	    
        	    
     	    every= every.replaceAll("\\}\\{", "\\}\\}\\{\\{");

     	    String[] parts = every.split("\\}\\{");
     	    
        	getCount(elasticip, target);
     	    for (String part: parts){
     	    	if (part.contains("_type") && (part.contains("doc")||part.contains("pcap_file") )){
     	    		continue;
     	    	}
//     	    	System.out.print("----------------");
  //   	    	System.out.print(part);
     	    	
     	    	int strart = part.indexOf("timestamp");
     	    	if (strart >0) {
     	    		int end = part.indexOf("\",");
     	    		String timestring = part.substring(strart+12+1, end);
     	    		//System.out.print(timestring);
     	    		Instant instant = Instant.ofEpochMilli(Long.parseLong(timestring));
     	    		DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

     	    		String dateAsText = fmt.format(instant.atZone(ZoneId.systemDefault())).toString();
	     	    	part= part.replaceAll("timestamp", "@timestamp");
	     	    	part= part.replaceAll(timestring, dateAsText);
	     	    	System.out.print("\n");
	     	    	
     	    	}
     	    	
     	    	System.out.print( part);	
     	    	System.out.print("\n");
     	    	sendpacket( part,elasticip, target );
     	    }
		
    }
    
    
    public static void sendpacket(String data,String elasticip, String target ){
    	try {
    		count+=1;
    		URL url = new URL(String.format("http://%s:9200/%s/_doc/%d",elasticip, target, count));
    		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
    		httpConn.setRequestMethod("PUT");

    		httpConn.setRequestProperty("Content-Type", "application/json");

    		byte[] message = ("elastic:changeme").getBytes("UTF-8");
    		String basicAuth = DatatypeConverter.printBase64Binary(message);
    		httpConn.setRequestProperty("Authorization", "Basic " + basicAuth);

    		httpConn.setDoOutput(true);
    		OutputStreamWriter writer = new OutputStreamWriter(httpConn.getOutputStream());
    		writer.write(data);
    		writer.flush();
    		writer.close();
    		httpConn.getOutputStream().close();

    		InputStream responseStream = httpConn.getResponseCode() / 100 == 2
    				? httpConn.getInputStream()
    				: httpConn.getErrorStream();
    		Scanner s = new Scanner(responseStream).useDelimiter("\\A");
    		String response = s.hasNext() ? s.next() : "";

    		System.out.println(response);
	    }catch(Exception e) {
	    	System.out.println(e);
	    }
    }
    public static void getCount(String elasticip, String target){
    	// POST test_index1/_count
    	System.out.println("POST test_index1/_count");
    	try {
    		URL url = new URL(String.format("http://%s:9200/%s/_count",elasticip, target));
    		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
    		httpConn.setRequestMethod("POST");

    		byte[] message = ("elastic:changeme").getBytes("UTF-8");
    		String basicAuth = DatatypeConverter.printBase64Binary(message);
    		httpConn.setRequestProperty("Authorization", "Basic " + basicAuth);

    		InputStream responseStream = httpConn.getResponseCode() / 100 == 2
    				? httpConn.getInputStream()
    				: httpConn.getErrorStream();
    		Scanner s = new Scanner(responseStream).useDelimiter("\\A");
    		String response = s.hasNext() ? s.next() : "";
    		int start = response.indexOf("count");
    		int end = response.indexOf(",");
    		System.out.println(String.format("%d,%d\n",start,end ));
    		String response1 = response.substring(start+7, end);
    		count = Integer.valueOf(response1);
    		
    		System.out.println(response);
	    }catch(Exception e) {
	    	System.out.println(e);
	    }
    }
    
   
}
