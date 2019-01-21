# Run genreport inside of Docker:
# $ docker build . -t edns-compliance-test
# $ echo 'zone.tld' | docker run -i edns-compliance-test 
# Read the help:
# $ docker run -i edns-compliance-test -h
# Only test IPv4:
# $ echo 'zone.tld' | docker run -i edns-compliance-test -4

FROM ubuntu:latest
COPY . .
RUN apt-get update
RUN apt-get -y install build-essential \
                       autoconf \
                       automake \
                       pkg-config \
                       libssl-dev
RUN autoreconf -fis && \
    ./configure && \
    make && \
    make install
ENTRYPOINT [ "genreport" ]
