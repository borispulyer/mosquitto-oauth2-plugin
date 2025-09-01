# Define versions
ARG MOSQUITTO_VERSION=2.0.21
ARG LWS_VERSION=4.3.5


##
# First Stage:
# Build Mosquitto with Alpine
##
FROM alpine:edge AS mosquitto_builder
ARG MOSQUITTO_VERSION
ARG LWS_VERSION

# Get build dependencies
RUN set -x && \
    apk --no-cache add --virtual .build-deps \
    build-base \
    cmake \
    openssl-dev \
    curl-dev \
    cjson-dev \
    gnupg \
    linux-headers \
    util-linux-dev \
    ca-certificates \
    git wget tar xz


# Build libwebsockets
WORKDIR /build/lws
RUN set -x && \
    wget https://github.com/warmcat/libwebsockets/archive/v${LWS_VERSION}.tar.gz -O /tmp/lws.tar.gz && \
    tar -xf /tmp/lws.tar.gz --strip=1 -C . && \
    rm /tmp/lws.tar.gz && \
    cmake . \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \ 
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DDISABLE_WERROR=ON \
    -DLWS_IPV6=ON \
    -DLWS_WITHOUT_BUILTIN_GETIFADDRS=ON \
    -DLWS_WITHOUT_CLIENT=ON \
    -DLWS_WITHOUT_EXTENSIONS=ON \
    -DLWS_WITHOUT_TESTAPPS=ON \
    -DLWS_WITH_EXTERNAL_POLL=ON \
    -DLWS_WITH_HTTP2=OFF \
    -DLWS_WITH_SHARED=OFF \
    -DLWS_WITH_ZIP_FOPS=OFF \
    -DLWS_WITH_ZLIB=OFF && \
    make -j "$(nproc)" && \
    make install && \
    rm -rf /root/.cmake

# Build Mosquitto
WORKDIR /build/mosquitto
RUN set -x && \
    wget https://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz -O /tmp/mosquitto.tar.gz && \
    tar -xf /tmp/mosquitto.tar.gz --strip=1 -C . && \
    rm /tmp/mosquitto.tar.gz && \
    make -C . -j "$(nproc)" \
    CFLAGS="-Wall -O2 -I/usr/local/include" \
    LDFLAGS="-L/usr/local/lib" \
    WITH_ADNS=no \
    WITH_DOCS=no \
    WITH_SHARED_LIBRARIES=yes \
    WITH_SRV=no \
    WITH_STRIP=yes \
    WITH_WEBSOCKETS=yes \
    prefix=/usr/local \
    binary && \
    make install

# Build OAuth2 Plugin
WORKDIR /build/oauth2-plugin
COPY ./src/ .
RUN set -x && \
    gcc -fPIC -shared \
    -I/usr/local/include \
    -I/usr/include/cjson  \
    -o oauth2-plugin.so \
    ./*.c \
    -lcurl -lmosquitto -lcjson


##
# Final Stage:
# Runtime
##
FROM alpine:edge AS runtime

# Get minimal runtime dependencies
RUN apk add --no-cache \
    curl \
    cjson \
    openssl \
    ca-certificates \
    tzdata

# Copy binaries
COPY --from=mosquitto_builder /usr/local/sbin/mosquitto* /usr/local/sbin/
COPY --from=mosquitto_builder /usr/local/bin/mosquitto* /usr/local/bin/
COPY --from=mosquitto_builder /usr/local/lib/libmosquitto* /usr/local/lib/
COPY --from=mosquitto_builder /build/oauth2-plugin/oauth2-plugin.so /mosquitto/plugins/oauth2-plugin.so


RUN set -x && \
    addgroup -g 1883 -S mosquitto && \
    adduser -S -u 1883 -D -H -h /var/empty -s /sbin/nologin -G mosquitto -g mosquitto mosquitto && \
    mkdir -p /mosquitto/config /mosquitto/data /mosquitto/logs /mosquitto/auth && \
    chown -R mosquitto:mosquitto /mosquitto

VOLUME ["/mosquitto/config", "/mosquitto/data", "/mosquitto/logs", "/mosquitto/auth"]

EXPOSE 1883 9001

COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/local/sbin/mosquitto" ,"-c", "/mosquitto/config/mosquitto.conf"]