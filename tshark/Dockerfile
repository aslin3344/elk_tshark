FROM alpine
RUN apk --no-cache --update add py-pip curl tshark bash openjdk17
RUN pip install --upgrade pip
RUN rm -rf /tmp/* /var/cache/apk/* /root/*
RUN mkdir -p /var/log/java
VOLUME ["/data/pcap"]
ADD bin /usr/bin
WORKDIR /var/log/java
CMD ["bash"]