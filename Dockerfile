###################################################
# Build broker
###################################################

#Start from a new image.
FROM debian:bookworm-slim

RUN set -ex; \
    apt update; DEBIAN_FRONTEND=noninteractive \
    apt install -y \
    openssl \
    uuid \
    tini \
    wget \
    make \
    g++ \
    # gdb \ 
    # gdbserver \ 
    cmake \
    file \
    git \
    pkg-config \
    libssl-dev \
    libcjson-dev \
    libcrypto++-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --shell /bin/false --user-group --no-log-init flashmq

WORKDIR /app/flashmq

RUN mkdir -p /app/flashmq/auth-plugin
# Copy all the contents of auth-plugin directory to the container
COPY ./auth-plugin /app/flashmq/auth-plugin
# check if COPY was successful
RUN if [ -d /app/flashmq/auth-plugin ]; then echo "auth-plugin directory copied successfully"; else echo "auth-plugin directory copy failed"; exit 1; fi
# check if the build script exists
RUN if [ -f /app/flashmq/auth-plugin/build.sh ]; then echo "build.sh found"; else echo "build.sh not found, exiting"; exit 1; fi
RUN ./auth-plugin/build.sh
# check if the build was successful
RUN if [ -f /app/flashmq/build-plugin-libcurl-Release/libplugin_libcurl.so ]; then echo "libplugin_libcurl.so found, copying to /app/flashmq"; else echo "libplugin_libcurl.so not found, exiting"; exit 1; fi
RUN cp /app/flashmq/build-plugin-libcurl-Release/libplugin_libcurl.so /app/flashmq/libplugin_libcurl.so


# Clone the FlashMQ repository
ARG FLASHMQ_VERSION="v1.21.1"
# RUN git clone https://github.com/halfgaar/FlashMQ.git

# RUN git checkout tag v1.21.1
RUN git clone --branch ${FLASHMQ_VERSION} https://github.com/halfgaar/FlashMQ.git

WORKDIR /app/flashmq/FlashMQ

RUN ./build.sh

RUN cp /app/flashmq/FlashMQ/FlashMQBuildRelease/flashmq /bin/flashmq
COPY ./flashmq.conf /etc/flashmq/flashmq.conf

EXPOSE 1883
ENTRYPOINT /usr/bin/flashmq
CMD ["--config-file" "/etc/flashmq/flashmq.conf"]