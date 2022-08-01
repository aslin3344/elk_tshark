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
	private static boolean debug = false;

	//tshark -r /data/pcap/scada.pcapng -T ek | jq '.' | java -jar log-generator-0.0.2.jar
	
    public static void main(String[] args) throws InterruptedException, IOException {
 
    	
    	

    	

            //String cmd = "tshark -r /data/pcap/scada.pcapng -T ek | jq '.'";
        /*  String cmd = "C:\\Program Files\\Wireshark\\tshark.exe -r C:\\Users\\65935\\Downloads\\docker-elk-main\\tshark\\logtest\\log\\scada.pcapng -T ek "     ;    
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String elasticip ="localhost";
            String target = "test7";
            */
    
    		String elasticip = args[0];  
    		String target = args[1];  
    		if (args.length>2) {
    			debug =true;
    		}			
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
              
            
          	StringBuilder everything = new StringBuilder();
     	    String lineeach;
     	    while( (lineeach = in.readLine()) != null) {
     	       everything.append(lineeach);
     	    }
     	    System.out.print("---------everything-----------\n");

     	    String every= everything.toString();
     	    
     	    
        	    
     	    every= every.replaceAll("\\}\\{", "\\}\\}\\{\\{");

     	    String[] parts = every.split("\\}\\{");
     	    
        	getCount(elasticip, target);
     	    for (String part: parts){
     	    	
     	    	if (part.contains("_type") && (part.contains("doc")||part.contains("pcap_file") )){
     	    		continue;
     	    	}
     	    	if (debug ==true){
	    	    	System.out.print("-------1---------\n");
	     	    	System.out.print(part);
	     	    	System.out.print("\n");	
	     	    	System.out.print("--------2--------\n");
     	    	}
     	    	int start = part.indexOf("timestamp");
     	    	if (start >0) {
     	    		int end = part.indexOf("\",");
     	    		String timestring = part.substring(start+12, end);
     	    		if (debug ==true){
	     	    		System.out.print(timestring);
	     	    		System.out.print("\n");	
     	    		}
     	    		//Instant instant = Instant.ofEpochMilli(Long.parseLong(timestring));
     	    		//DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd' 'hh:mm:ssX");

     	    		//String dateAsText = fmt.format(instant.atZone(ZoneId.systemDefault())).toString();
	     	    	part= part.replaceAll("timestamp", "@timestamp");
	     	    	//part= part.replaceAll(timestring, dateAsText);
	     	    	
	     	    	
     	    	}
     	    	if (debug ==true){
	     	    	System.out.print( part);	
	     	    	System.out.print("\n");
     	    	}
 
     	    	
/*     	    	part = "{\"@timestamp\":\"1506652627825\",\"layers\":{\"frame\":{\"frame_frame_interface_id\":\"0\",\"frame_frame_interface_name\":\"\\\\Device\\\\NPF_{544FE132-5B34-41C5-9D67-77487D592AFE}\","
     	    			+ "\"frame_frame_encap_type\":\"1\",\"frame_frame_time\":\"2017-09-29T02:37:07.825503000Z\",\"frame_frame_offset_shift\":\"0.000000000\","
     	    			+ "\"frame_frame_time_epoch\":\"1506652627.825503000\",\"frame_frame_time_delta\":\"0.005493000\",\"frame_frame_time_delta_displayed\":\"0.005493000\","
     	    			+ "\"frame_frame_time_relative\":\"0.005493000\",\"frame_frame_number\":\"2\",\"frame_frame_len\":\"451\",\"frame_frame_cap_len\":\"451\",\"frame_frame_marked\":false,"
     	    			+ "\"frame_frame_ignored\":false,\"frame_frame_protocols\":\"eth:ethertype:ip:tcp:data\"},\"eth\":{\"eth_eth_dst\":\"50:65:f3:2e:f8:f1\","
     	    			+ "\"eth_eth_dst_resolved\":\"HewlettP_2e:f8:f1\",\"eth_eth_dst_oui\":\"5268979\",\"eth_eth_dst_oui_resolved\":\"Hewlett Packard\","
     	    			+ "\"eth_eth_addr\":\"50:65:f3:2e:f8:f1\",\"eth_eth_addr_resolved\":\"HewlettP_2e:f8:f1\",\"eth_eth_addr_oui\":\"5268979\",\"eth_eth_addr_oui_resolved\":\"Hewlett Packard\","
     	    			+ "\"eth_eth_dst_lg\":false,\"eth_eth_lg\":false,\"eth_eth_dst_ig\":false,\"eth_eth_ig\":false,\"eth_eth_src\":\"ec:74:ba:27:3b:1a\",\"eth_eth_src_resolved\":\"Hirschma_27:3b:1a\","
     	    			+ "\"eth_eth_src_oui\":\"15496378\",\"eth_eth_src_oui_resolved\":\"Hirschmann Automation and Control GmbH\"},\"ip\":{\"ip_ip_version\":\"4\",\"ip_ip_hdr_len\":\"20\",\"ip_ip_dsfield\":\"0x00000000\",\"ip_ip_dsfield_dscp\":\"0\",\"ip_ip_dsfield_ecn\":\"0\",\"ip_ip_len\":\"437\","
     	    			+ "\"ip_ip_id\":\"0x0000e044\",\"ip_ip_flags\":\"0x00000040\",\"ip_ip_flags_rb\":false,\"ip_ip_flags_df\":true,\"ip_ip_flags_mf\":false,\"ip_ip_frag_offset\":\"0\",\"ip_ip_ttl\":\"63\",\"ip_ip_proto\":\"6\","
     	    			+ "\"ip_ip_checksum\":\"0x0000f876\",\"ip_ip_checksum_status\":\"1\",\"ip_ip_checksum_calculated\":\"0x0000f876\",\"ip_ip_src\":\"172.16.4.41\",\"ip_ip_addr\":[\"172.16.4.41\",\"172.18.5.60\"],"
     	    			+ "\"ip_ip_src_host\":\"172.16.4.41\",\"ip_ip_host\":[\"172.16.4.41\",\"172.18.5.60\"],\"ip_ip_dst\":\"172.18.5.60\",\"ip_ip_dst_host\":\"172.18.5.60\"},\"tcp\":{\"tcp_tcp_srcport\":\"2455\",\"tcp_tcp_dstport\":\"53353\","
     	    			+ "\"tcp_tcp_port\":[\"2455\",\"53353\"],\"tcp_tcp_stream\":\"0\",\"tcp_tcp_len\":\"397\",\"tcp_tcp_seq\":\"1\",\"tcp_tcp_seq_raw\":\"2919877050\",\"tcp_tcp_nxtseq\":\"398\",\"tcp_tcp_ack\":\"27\",\"tcp_tcp_ack_raw\":\"2851822371\","
     	    			+ "\"tcp_tcp_hdr_len\":\"20\",\"tcp_tcp_flags\":\"0x00000018\",\"tcp_tcp_flags_res\":false,\"tcp_tcp_flags_ns\":false,\"tcp_tcp_flags_cwr\":false,\"tcp_tcp_flags_ecn\":false,\"tcp_tcp_flags_urg\":false,\"tcp_tcp_flags_ack\":true,"
     	    			+ "\"tcp_tcp_flags_push\":true,\"tcp_tcp_flags_reset\":false,\"tcp_tcp_flags_syn\":false,\"tcp_tcp_flags_fin\":false,\"tcp_tcp_flags_str\":\"·······AP···\",\"tcp_tcp_window_size_value\":\"7738\","
     	    			+ "\"tcp_tcp_window_size\":\"7738\",\"tcp_tcp_window_size_scalefactor\":\"-1\",\"tcp_tcp_checksum\":\"0x00001ec1\",\"tcp_tcp_checksum_status\":\"1\",\"tcp_tcp_checksum_calculated\":\"0x00001ec1\",\"tcp_tcp_urgent_pointer\":\"0\","
     	    			+ "\"tcp_tcp_analysis\":null,\"tcp_tcp_analysis_acks_frame\":\"1\",\"tcp_tcp_analysis_ack_rtt\":\"0.005493000\",\"tcp_tcp_analysis_bytes_in_flight\":\"397\",\"tcp_tcp_analysis_push_bytes_sent\":\"397\",\"text\":\"Timestamps\","
     	    			+ "\"tcp_tcp_time_relative\":\"0.005493000\",\"tcp_tcp_time_delta\":\"0.005493000\",\"tcp_tcp_payload\":\"cc:cc:01:00:75:01:00:00:00:00:00:00:01:00:00:00:00:00:00:00:07:00:00:00:00:00:05:00:00:00:62:b1:cd:59:01:06:01:01:4d:1d:01:01:01:00:00:00:00:00:a0:bb:44:33:33:57:42:01:01:00:00:cd:8c:bb:44:67:66:52:42:00:00:01:01:00:00:00:00:33:93:bb:44:00:00:81:42:01:00:00:01:1e:ad:bb:44:01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00:00:01:00:01:01:00:01:01\"},\"data\":{\"data_data_data\":\"cc:cc:01:00:75:01:00:00:00:00:00:00:01:00:00:00:00:00:00:00:07:00:00:00:00:00:05:00:00:00:62:b1:cd:59:01:06:01:01:4d:1d:01:01:01:00:00:00:00:00:a0:bb:44:33:33:57:42:01:01:00:00:cd:8c:bb:44:67:66:52:42:00:00:01:01:00:00:00:00:33:93:bb:44:00:00:81:42:01:00:00:01:1e:ad:bb:44:01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00:00:01:00:01:01:00:01:01\",\"data_data_len\":\"397\"}}}\r\n"
     	    			+ "";
   */
     	    	
     	    	
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
    		//System.out.println(String.format("%d,%d\n",start,end ));
    		String response1 = response.substring(start+7, end);
    		count = Integer.valueOf(response1);
    	
    		System.out.println(response);
    
	    }catch(Exception e) {
	    	System.out.println(e);
	    }
    }
    
   
}
