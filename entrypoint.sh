#!/bin/bash -e

echo "Starting the RTK GPS client (ntrip_client)"

mkdir -p ~/.ros/log

ros-with-env ros2 launch ntrip_client ntrip_client_launch.py
