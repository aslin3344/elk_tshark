package logtest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;



public class logtest {
	private static int count = 0;

	//tshark -r /data/pcap/scada.pcapng -T ek | jq '.' | java -jar log-generator-0.0.2.jar
	
    public static void main(String[] args) throws InterruptedException, IOException {
 

            //String cmd = "tshark -r /data/pcap/scada.pcapng -T ek | jq '.'";
            //String cmd = "C:\\Program Files\\Wireshark\\tshark.exe -r C:\\Users\\65935\\Downloads\\docker-elk-main\\tshark\\logtest\\log\\scada.pcapng -T ek"         
            //Process p = Runtime.getRuntime().exec(cmd);
            //BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
    	
//            
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
          	StringBuilder everything = new StringBuilder();
     	    String lineeach;
     	    while( (lineeach = in.readLine()) != null) {
     	       everything.append(lineeach);
     	    }
     	    System.out.print("---------everything-----------");
     	    //System.out.print( everything.toString());

     	    String every= everything.toString();
     	    every= every.replaceAll("\\}\\{", "\\}\\}\\{\\{");
     	    String[] parts = every.split("\\}\\{");
     	    for (String part: parts){
     	    	if (part.contains("_type") && part.contains("doc")){
     	    		continue;
     	    	}
     	    	//System.out.print( part);	
     	    	//System.out.print("\n");
     	    	sendpacket( part);
     	    }

    }
    
    
    public static void sendpacket(String data){
    	try {
    		URL url = new URL(String.format("http://192.168.65.2:9200/test_index2/_doc/%d",count));
    		count+=1;
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

}
