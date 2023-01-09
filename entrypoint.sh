#!/bin/bash -e

source /opt/ros/humble/setup.bash

# The mesh-com project had issues resolving packages without this.
export PYTHONPATH=/opt/ros/humble/lib/python3.8/site-packages

echo "Starting the RTK GPS client (ntrip_client)"

mkdir -p ~/.ros/log

ros2 launch ntrip_client ntrip_client_launch.py
