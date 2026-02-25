# Given dynamically from CI job.
FROM --platform=${BUILDPLATFORM:-linux/amd64} ghcr.io/tiiuae/fog-ros-sdk:v3.4.0-${TARGETARCH:-amd64} AS builder

# Must be defined another time after "FROM" keyword.
ARG TARGETARCH

COPY . $SRC_DIR/ntrip_client

RUN /packaging/build_colcon_sdk.sh ${TARGETARCH:-amd64}

#  ▲               runtime ──┐
#  └── build                 ▼

FROM ghcr.io/tiiuae/pkcs11-closer:sha-7bec028 AS closer

# 1. Restore this stage so the name 'ros-keyring' exists
FROM ubuntu:22.04 AS ros-keyring
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key \
            -o /ros-archive-keyring.gpg

# 2. This stage now correctly finds --from=ros-keyring
FROM ubuntu:22.04 AS ros-deps-fetcher
COPY --from=ros-keyring /ros-archive-keyring.gpg /usr/share/keyrings/ros-archive-keyring.gpg
RUN (apt-get update || (sleep 5 && apt-get update)) && apt-get install -y --no-install-recommends ca-certificates \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu jammy main" > /etc/apt/sources.list.d/ros2.list \
    && apt-get update \
    && mkdir -p /extracted_deps_root /downloaded_debs \
    && cd /downloaded_debs \
    && apt-get download \
         ros-humble-nmea-msgs \
         ros-humble-rmw-cyclonedds-cpp \
         ros-humble-ros-environment \
         ros-humble-cyclonedds \
    && for pkg in *.deb; do dpkg-deb -x "$pkg" /extracted_deps_root; done

# 3. Final Stage
FROM ghcr.io/tiiuae/fog-ros-baseimage:v3.4.0
RUN mkdir -p /tmp && chmod 1777 /tmp

# Prevent 'unbound variable' crashes in ROS setup scripts
ENV AMENT_TRACE_SETUP_FILES=
ENV AMENT_PYTHON_EXECUTABLE=/usr/bin/python3
ENV PYTHONPATH=/opt/ros/humble/local/lib/python3.10/dist-packages:/opt/ros/humble/lib/python3.10/site-packages:${PYTHONPATH}

# Copy ONLY the safe ROS layer files, without overwriting the base OS
COPY --from=ros-deps-fetcher /extracted_deps_root /

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]

COPY --from=closer /pkcs11-closer /
COPY --from=builder $INSTALL_DIR $INSTALL_DIR

ENV RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
