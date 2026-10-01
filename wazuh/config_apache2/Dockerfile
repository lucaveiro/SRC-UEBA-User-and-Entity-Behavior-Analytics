FROM debian:stable

RUN apt update && apt install -y nano vim bash
RUN apt install -y iproute2 iputils-ping net-tools socat psmisc
RUN apt install -y apache2 
RUN apt install -y rsyslog

RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

CMD rsyslogd && apache2ctl -D FOREGROUND
