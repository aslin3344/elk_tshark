package logtest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketRequest implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(PacketRequest.class);
    private final String data;

    public PacketRequest(final String data) {
        this.data = data;
    }

    @Override
    public void run() {
        log.info("{}", data);
    }
}
