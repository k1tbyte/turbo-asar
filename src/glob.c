//
// Created by kitbyte on 11.11.2025.
//

#include <stddef.h>
#include "glob.h"

#include <stdlib.h>
#include <string.h>


char* normalize_glob_pattern(const char* pat) {

	if (pat == NULL) {
		return NULL;
	}

	char* pattern_copy = strdup(pat);

#ifndef __WINDOWS__
	return pattern_copy;
#else
	size_t extra = 0, length = 0;

	for (const char* p = pattern_copy; *p; p++) {
		if (*p == '/') extra++;
		length++;
	}

	if (extra == 0) {
		return pattern_copy;
	}

	const size_t new_len = length + extra;

	char* new_pat = malloc(new_len + 1);
	if (!new_pat) {
		return pattern_copy; // Fallback on allocation failure
	}

	char* w = new_pat;

	for (size_t i = 0; i < length; i++) {
		if (pattern_copy[i] == '/') {
			*w++ = '\\';
			*w++ = '\\';
		} else {
			*w++ = pattern_copy[i];
		}
	}

	*w = '\0';
	free(pattern_copy);
	return new_pat;
#endif
}


bool __pure glob_match(char const *pat, char const *str)
{
	/*
	 * Backtrack to previous * on mismatch and retry starting one
	 * character later in the string.  Because * matches all characters
	 * (no exception for /), it can be easily proved that there's
	 * never a need to backtrack multiple levels.
	 */
	char const *back_pat = NULL, *back_str;

	/*
	 * Loop over each token (character or class) in pat, matching
	 * it against the remaining unmatched tail of str.  Return false
	 * on mismatch, or true after matching the trailing nul bytes.
	 */
	for (;;) {
		unsigned char c = *str++;
		unsigned char d = *pat++;

		switch (d) {
		case '?':	/* Wildcard: anything but nul */
			if (c == '\0')
				return false;
			break;
		case '*':	/* Any-length wildcard */
			if (*pat == '\0')	/* Optimize trailing * case */
				return true;
			back_pat = pat;
			back_str = --str;	/* Allow zero-length match */
			break;
		case '[': {	/* Character class */
			if (c == '\0')	/* No possible match */
				return false;
			bool match = false, inverted = (*pat == '!');
			char const *class = pat + inverted;
			unsigned char a = *class++;

			/*
			 * Iterate over each span in the character class.
			 * A span is either a single character a, or a
			 * range a-b.  The first span may begin with ']'.
			 */
			do {
				unsigned char b = a;

				if (a == '\0')	/* Malformed */
					goto literal;

				if (class[0] == '-' && class[1] != ']') {
					b = class[1];

					if (b == '\0')
						goto literal;

					class += 2;
					/* Any special action if a > b? */
				}
				match |= (a <= c && c <= b);
			} while ((a = *class++) != ']');

			if (match == inverted)
				goto backtrack;
			pat = class;
			}
			break;
		case '\\':
			d = *pat++;
			fallthrough;
		default:	/* Literal character */
literal:
			if (c == d) {
				if (d == '\0')
					return true;
				break;
			}
backtrack:
			if (c == '\0' || !back_pat)
				return false;	/* No point continuing */
			/* Try again from last *, one character later in str. */
			pat = back_pat;
			str = ++back_str;
			break;
		}
	}
}