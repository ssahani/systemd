/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "time-util.h"

typedef struct Link Link;
typedef struct Network Network;

int nat464_start(Link *link);
int nat464_stop(Link *link);
void nat464_flush(Link *link);

int link_request_nat464(Link *link);
