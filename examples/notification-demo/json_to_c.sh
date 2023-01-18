#!/bin/bash

# json_to_c.sh
#
# Copyright (C) 2022-2023 wolfSSL Inc.
#
# This file is part of wolfSentry.
#
# wolfSentry is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSentry is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

echo "static const char* wolfsentry_config_data = " > notify-config.h
cat notify-config.json | sed -e 's/\\/\\\\/g;s/"/\\"/g;s/^/"/;s/$/\\n"/' >> notify-config.h
echo ";" >> notify-config.h
