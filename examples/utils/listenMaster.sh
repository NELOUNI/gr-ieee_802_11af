#!/bin/bash
xterm -hold -e "ncat -u -l -p 3334 | tee utils/listenMaster"
