#!/bin/bash

echo "static const char* wolfsentry_config_data = " > notify-config.h
cat notify-config.json | sed -e 's/\\/\\\\/g;s/"/\\"/g;s/^/"/;s/$/\\n"/' >> notify-config.h
echo ";" >> notify-config.h
