/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-util.h"

typedef struct Link Link;

int dhcp6_server_configure(Link *link);
