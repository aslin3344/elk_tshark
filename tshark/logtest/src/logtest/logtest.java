package logtest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class logtest {
	private static final Logger log = LoggerFactory.getLogger(logtest.class);
    private static AtomicLong total = new AtomicLong(0);

    public static void main(String[] args) throws InterruptedException, IOException {

  
        // init
        log.trace("starting");
        final long start = System.nanoTime();
  

        // add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                long elapsed_loop = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
          
                log.trace("shutdown");
            }
        });
        
        //tshark -r /data/pcap/mypcap.pcap -T ek
        
        
        

        // will be repeated every params.repeat milliseconds
        do {
        	System.out.print("start....");
            LogExecutor executor = new LogExecutor(1);
            
            String line;
            Process p = Runtime.getRuntime().exec("tshark -r /data/pcap/scada.pcapng -T ek");
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = in.readLine()) != null) {
            	 //System.out.print(line);
                // TODO: Handle input line
                 executor.add(new PacketRequest(line));
            }
        
            // wait the end
            executor.finish();
            Thread.sleep(1000);
        } while (true);

    }

}
