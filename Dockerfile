ARG TARGETARCH

FROM ghcr.io/tiiuae/tii-px4-msgs:sha-77f972d-${TARGETARCH:-amd64}-humble AS px4msgs

FROM ros:humble-ros-core-jammy AS base

RUN --mount=type=bind,from=px4msgs,source=/artifacts,target=/artifacts \
    apt-get update \
    && apt-get install -y --no-install-recommends /artifacts/*.deb \
        python3-numpy \
        ros-humble-launch-xml \
        ros-humble-mavros-msgs \
        ros-humble-nmea-msgs \
        ros-humble-ros2launch \
    && rm -rf /var/lib/apt/lists/*

FROM base AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3-colcon-common-extensions \
        python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ws
COPY . src/ntrip_client

RUN . /opt/ros/humble/setup.sh \
    && colcon build \
        --merge-install \
        --install-base /opt/ntrip_client \
        --event-handlers console_direct+

FROM ghcr.io/tiiuae/pkcs11-closer:sha-7bec028 AS closer

FROM base AS runtime

WORKDIR /opt/ntrip_client

COPY --from=closer /pkcs11-closer /
COPY --from=builder /opt/ntrip_client/ /opt/ntrip_client/
COPY LICENSE /usr/share/doc/ntrip_client/LICENSE
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/ros_entrypoint.sh", "/entrypoint.sh"]
CMD []
