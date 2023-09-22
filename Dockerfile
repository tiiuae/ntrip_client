FROM ghcr.io/tiiuae/fog-ros-baseimage-builder:sha-6d67ecf AS builder

COPY . $SRC_DIR/ntrip_client

RUN /packaging/build_colcon.sh

#  ▲               runtime ──┐
#  └── build                 ▼

FROM ghcr.io/tiiuae/fog-ros-baseimage:sha-6d67ecf

RUN apt-get update \
    && apt-get install -y \
        nmea-msgs \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ros-with-env ros2 launch ntrip_client ntrip_client_launch.py

COPY --from=builder $INSTALL_DIR $INSTALL_DIR
