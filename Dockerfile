FROM ghcr.io/tiiuae/fog-ros-baseimage:builder-3dcb78d AS builder

# Install build dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    curl \
    python3-bloom \
    fakeroot \
    dh-make \
    dh-python \
    python3-pytest \
    && rm -rf /var/lib/apt/lists/*

# Build mesh_com
COPY . /main_ws/src/

# this:
# 1) builds the application
# 2) packages the application as .deb in /main_ws/
RUN /packaging/build.sh

#  ▲               runtime ──┐
#  └── build                 ▼

FROM ghcr.io/tiiuae/fog-ros-baseimage:sha-3dcb78d

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    ros-${ROS_DISTRO}-mavros-msgs \
    ros-${ROS_DISTRO}-nmea-msgs \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/entrypoint.sh" ]

COPY entrypoint.sh /entrypoint.sh

COPY --from=builder /main_ws/ros-*-ntrip-client_*_amd64.deb /ntrip_client.deb

RUN dpkg -i /ntrip_client.deb && rm /ntrip_client.deb