#!/bin/bash -e

source /opt/ros/humble/setup.bash

echo "Starting the RTK GPS client (ntrip_client)"

mkdir -p ~/.ros/log

ros2 launch ntrip_client ntrip_client_launch.py
