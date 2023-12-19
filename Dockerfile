# Given dynamically from CI job.
FROM --platform=${BUILDPLATFORM:-linux/amd64} ghcr.io/tiiuae/fog-ros-sdk:v3.1.0-${TARGETARCH:-amd64} AS builder

# Must be defined another time after "FROM" keyword.
ARG TARGETARCH

COPY . $SRC_DIR/ntrip_client

RUN /packaging/build_colcon_sdk.sh ${TARGETARCH:-amd64}

#  ▲               runtime ──┐
#  └── build                 ▼

FROM ghcr.io/tiiuae/fog-ros-baseimage:v3.1.0

RUN apt-get update \
    && apt-get install -y \
        nmea-msgs \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]

COPY --from=builder $INSTALL_DIR $INSTALL_DIR
