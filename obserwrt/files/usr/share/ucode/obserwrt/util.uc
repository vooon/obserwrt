/* Shared configuration and observation helpers. */
"use strict";

/* Match OpenWrt's get_bool() accepted spellings. */
export function bool_option(value, fallback)
{
	switch (value) {
	case '1':
	case 'on':
	case 'true':
	case 'yes':
	case 'enabled':
		return true;
	case '0':
	case 'off':
	case 'false':
	case 'no':
	case 'disabled':
		return false;
	default:
		return fallback;
	}
};
