#!/bin/bash

ping -c 1000 insec -i 0.010 | awk -F'/' 'END{ print "Average RTT:", $5, "ms" }'
