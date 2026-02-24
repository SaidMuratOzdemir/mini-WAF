FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends squid ca-certificates apache2-utils && \
    rm -rf /var/lib/apt/lists/*

COPY bootstrap-squid.conf /opt/squid/bootstrap-squid.conf
COPY docker-entrypoint.sh /usr/local/bin/forward-proxy-entrypoint.sh
RUN chmod +x /usr/local/bin/forward-proxy-entrypoint.sh

EXPOSE 3128

CMD ["/usr/local/bin/forward-proxy-entrypoint.sh"]
