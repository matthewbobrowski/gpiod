// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Matthew Bobrowski <matthew@bobrowski.net>
 */

#ifndef GPIOD_H
#define GPIOD_H

#define GPIOD_DOMAIN_SOCK "/var/run/gpiod.sock"

#define BUF_SZ 4096

enum result_codes {
	SUCCESS = 0,
	FAILURE,
};

enum request_types {
	GET = 0,
	SET,
	LIST,
	INFO,
};

struct request {
	int type;
	size_t len;
	char data[0];
};

#endif /* GPIOD_H */
