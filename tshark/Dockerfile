FROM alpine
RUN apk --no-cache --update add py-pip tshark bash openjdk17 curl jq
RUN pip install --upgrade pip  
RUN rm -rf /tmp/* /var/cache/apk/* /root/*
RUN mkdir -p /var/log/java
VOLUME ["/data/pcap"]
ADD bin /usr/bin
WORKDIR /var/log/java
CMD ["bash"]