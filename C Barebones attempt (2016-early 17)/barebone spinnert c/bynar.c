#ifndef _BYNAR_H_
#define _BYNAR_H_


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>


#define bynar_int_t long long int
#define bynar_float_t long double

/* for a more portable size size */
#define bynar_length_int_t size_t

typedef enum {
	bynar_null,
	bynar_bool,
	bynar_int,
	bynar_float,
	bynar_string,
	bynar_dict,
	bynar_list,

	bynar_property,
	bynar_action,
	bynar_param
} bynar_type;


typedef struct _bynar_dict_entry {
	struct _bynar_value * key;
	struct _bynar_value * value;
} bynar_dict_entry;

// struct _bynar_list_entry { // linked list
// 	struct _bynar_value * value;
// 	struct _bynar_list_entry * next;
// } bynar_list_entry;

/** The represention of all bynar values types
*/
typedef struct _bynar_value {

	struct _bynar_value * parent;

	bynar_type type;

	union {
		int boolean;
		bynar_int_t integer;
		bynar_float_t flt;
		#define float_value flt;

		struct {
        	bynar_length_int_t length;
        	char * pointer;
      	} string;

		struct {
			bynar_length_int_t length;

			bynar_dict_entry * values;
		} dict;

		struct {
			bynar_length_int_t length;

			// struct bynar_list_entry * root_entry;
			struct _bynar_value ** values;
		} list;



	} u;

} bynar_value;

/** Used with lists and dicts for keeping track of
serization iterations and appending. */
typedef struct _bynar_sequence_builder {
	bynar_value value;

	size_t iter_count;
	size_t len_hint;

} bynar_sequence_builder;


/** Bynar functions */

bynar_value * bynar_list_new(size_t len_hint);
bynar_value * bynar_list_append(bynar_value * list, bynar_value * value);

bynar_value * bynar_dict_new(size_t len_hint);
bynar_value * bynar_dict_push(bynar_value * dict, bynar_value * key, bynar_value * value);
bynar_value * bynar_dict_get_string(bynar_value * dict, const char * search_key);

bynar_value * bynar_string_new_nocopy(char * string_value, size_t length);
bynar_value * bynar_string_new(const char * string_value_buf, size_t length);

bynar_value * bynar_dict_push_string_key(bynar_value * dict, const char * key, bynar_value * value);

bynar_value * bynar_int_new(bynar_int_t int_val);
bynar_value * bynar_float_new(bynar_float_t float_val);
bynar_value * bynar_bool_new(int bool_val);
bynar_value * bynar_null_new();

void bynar_serialize(char * out_buf, bynar_value * value);
size_t bynar_get_serialized_size(bynar_value * value);

bynar_value * bynar_deserialize(char * buf, size_t len, char *error_buf);

void bynar_free(bynar_value * value);

char * strchr_bynar_safe(const char * s, char c);


/* Creates a new empty list
len_hint = 0, okay
*/
bynar_value * bynar_list_new(size_t len_hint) {

	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_sequence_builder));

	if (!value)
		return NULL;

	value->type = bynar_list;

	/* Try to allocate space for list values with number = len */
	if (!( value->u.list.values = (bynar_value **) malloc(len_hint * sizeof(bynar_value *)) )) {
		free(value);
		return NULL;
	}

	((bynar_sequence_builder *) value)->len_hint = len_hint;

	return value;
}

/** Appends `bynar_value` to list */
bynar_value * bynar_list_append(bynar_value * list, bynar_value * value) {
	assert(list->type == bynar_list);

	if ( ((bynar_sequence_builder *)list)->len_hint > 0 ) {
		((bynar_sequence_builder *)list)->len_hint -= 1;
	} else {
		/* no space to append, so make it */
		bynar_value ** re_values = (bynar_value **) realloc(
			list->u.list.values,
			sizeof(bynar_value *) * (list->u.list.length + 1)
		);

		if (!re_values)
			return NULL;

		list->u.list.values = re_values;
	}

	/* once there is space, assign new ending spot to value argument */

	list->u.list.values[list->u.list.length] = value;
	list->u.list.length += 1;

	value->parent = list;

	return value;
}

/** Creates empty dict.
len_hint = 0 is okay
*/
bynar_value * bynar_dict_new(size_t len_hint) {

	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_sequence_builder));

	if (!value)
		return NULL;

	value->type = bynar_dict;

	/* Try to allocate space for list values with number = len */
	if (!( value->u.dict.values = (bynar_dict_entry *) calloc(len_hint, sizeof(*value->u.dict.values)) )) {
		free(value);
		return NULL;
	}

	((bynar_sequence_builder *) value)->len_hint = len_hint;

	return value;
}

/** Creates a new entry in the dict with `bynar_value` type key and value

The key must be a `bynar_string`

Duplicate key will update the key's value

TODO check over this function with someone with better C skills

*/
bynar_value * bynar_dict_push(bynar_value * dict, bynar_value * key, bynar_value * value) {
	assert(dict->type == bynar_dict);

	/* Only string for key -- null used for dict creation */
	assert(key->type == bynar_string || key->type == bynar_null); // || key->type == bynar_int ??

	bynar_value * found_value = bynar_dict_get_string(dict, key->u.string.pointer);

	if (found_value != NULL) { /* overwrite key if exists */

		value->parent = found_value->parent;

		found_value = realloc(found_value, sizeof(*value)); /* get possible bigger size for dict/list */
		*found_value = *value;

		value->parent = NULL;// needed so it does not try to free parent too
		bynar_free(value);

		return found_value;
	}

	if ( ((bynar_sequence_builder *)dict)->len_hint > 0 ) {
		((bynar_sequence_builder *)dict)->len_hint -= 1;
	} else {
		/* no space to append, so make it */
		bynar_dict_entry * re_values = (bynar_dict_entry *) realloc(
			dict->u.dict.values,
			sizeof(*dict->u.dict.values) * (dict->u.dict.length + 1)
		);

		if (!re_values)
			return NULL;

		dict->u.dict.values = re_values;
	}

	/* assign entry to a pointer destination at end of dict's values */
	bynar_dict_entry * entry = dict->u.dict.values + dict->u.dict.length;
	entry->key = key;
	entry->value = value;

	dict->u.dict.length += 1;

	key->parent = dict;
	value->parent = dict;

	return value;
}

bynar_value * bynar_dict_get_string(bynar_value * dict, const char * search_key) {
	assert(dict->type == bynar_dict);

	for (int i=0; i < dict->u.dict.length; i++) { // brute string iterative search

			if (!strncmp(
				dict->u.dict.values[i].key->u.string.pointer, search_key,
				  /*up to*/ dict->u.dict.values[i].key->u.string.length)
			  	) {

				return dict->u.dict.values[i].value;
			}

	}
	return NULL;
}


/** Creates bynar_string, but does not copy the buffer to another memory spot.
Use when string (char *) has been already allocated into safe memory
*/
bynar_value * bynar_string_new_nocopy(char * string_value, size_t length) {

	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_value));

	if (!value)
		return NULL;

	value->type = bynar_string;
	value->u.string.pointer = string_value;
	value->u.string.length = length;

	return value;
}

bynar_value * bynar_string_new(const char * string_value_buf, size_t length) {

	bynar_value * value;
	char * copy = (char *) malloc(length * sizeof(char));

	if (!copy)
		return NULL;

	memcpy(copy, string_value_buf, length * sizeof(char));
	// copy[length] = 0; // this would null termiate it (assuming malloc +1 more)

	if (! ( value = bynar_string_new_nocopy(copy, length) ) ) {
		free(copy);
		return NULL;
	}

	return value;
}

bynar_value * bynar_dict_push_string_key(bynar_value * dict, const char * key, bynar_value * value) {
	bynar_value *by_key = bynar_string_new(key, strlen(key));
	return bynar_dict_push(dict, by_key, value);
}


bynar_value * bynar_int_new(bynar_int_t int_val) {
	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_value));
	// calloc inits everything to NULL, namely `parent`

	if (!value)
		return NULL;

	value->type = bynar_int;
	value->u.integer = int_val;

	return value;
}

bynar_value * bynar_float_new(bynar_float_t float_val) {
	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_value));

	if (!value)
		return NULL;

	value->type = bynar_float;
	value->u.flt = float_val;

	return value;
}

bynar_value * bynar_bool_new(int bool_val) {
	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_value));

	if (!value)
		return NULL;

	value->type = bynar_bool;
	value->u.boolean = bool_val;

	return value;
}

bynar_value * bynar_null_new() {
	bynar_value * value = (bynar_value *) calloc(1, sizeof(bynar_value));

	if (!value)
		return NULL;

	value->type = bynar_null;

	return value;
}

#define seq_iter_count ((bynar_sequence_builder *) value)->iter_count

/** Serializes a bynar value into a char * buf

use `bynar_dump_count_value(bynar_value * value)` to
	determine the size of the buffer needed

*/
void bynar_serialize(char * out_buf, bynar_value * value) {

	while (value) {
		switch (value->type) {

			case bynar_int:
				out_buf += sprintf(out_buf, "i%lli;", value->u.integer);
				break;

			case bynar_float:
				// sprintf(out_buf, "f%Lf;", value->u.flt);
				out_buf += sprintf(out_buf, "f%Lg;", value->u.flt);
				break;

			case bynar_bool:
				*out_buf++ = value->u.boolean ? 'T' : 'F'; // assign, then ++
				break;

			case bynar_null:
				*out_buf++ = '\x00';
				// sprintf(out_buf, "n");
				break;

			case bynar_string: // `s[len]:[val]`

				out_buf += sprintf(out_buf, "s%zu:", value->u.string.length);

				for (size_t i=0;i < value->u.string.length; i++) {
					*out_buf++ = value->u.string.pointer[i];
				}
				break;

			case bynar_list:

				if (seq_iter_count == 0) {

					*out_buf++ = 'l';

					if (value->u.list.length == 0) {
						*out_buf++ = ';';
						break; // end the entire list, get out
					}
				}

				if (seq_iter_count == value->u.list.length) {
					*out_buf++ = ';'; /* end it on end */
					break;
				}

				seq_iter_count += 1; // doesn't work swapped lines
				value = value->u.list.values[seq_iter_count-1];

				continue; // start while again with next value
				// value = value->parent; done auto as last while() action

			case bynar_dict:
				if (seq_iter_count == 0) {

					*out_buf++ = 'd';

					if (value->u.dict.length == 0) {
						*out_buf++ = ';';
						break; // end the entire list, get out
					}
				}

				if (seq_iter_count == value->u.dict.length * 2) {
					*out_buf++ = ';'; /* end it as end */
					break;
				}

				seq_iter_count += 1;

				if (seq_iter_count & 1)
					value = value->u.dict.values[seq_iter_count/2].key;
				else
					value = value->u.dict.values[(seq_iter_count-1)/2].value;

				continue;

			default:
				printf("!*!*!defaulting in switch (%i)\n", value->type);
				break;
		}

		value = value->parent;
	}

}

/** Counts the number of charatcer the serialized string of a value will have */
size_t bynar_get_serialized_size(bynar_value * value) {

	size_t total = 0;

	while (value) {

		switch (value->type) {

			case bynar_int:
				total += snprintf(NULL, 0, "i%lli;", value->u.integer);
				break;
			case bynar_float:
				// sprintf(out_buf, "f%Lf;", value->u.flt);
				total += snprintf(NULL, 0, "f%Lg;", value->u.flt);
				break;
			case bynar_bool:
			case bynar_null:
				total += 1;
				break;

			case bynar_string:

				total += snprintf(NULL, 0, "s%zu:", value->u.string.length);
				total += value->u.string.length;

				break;

			case bynar_list:

				if (seq_iter_count == 0) {

					total += 1; /* 'l' */

					if (value->u.list.length == 0) {
						total += 1;  /* ';' */
						break;
					}
				}

				if (seq_iter_count == value->u.list.length) {
					total += 1; /* ';' */
					seq_iter_count = 0; /* clean up iter */
					break;
				}

				seq_iter_count += 1;
				value = value->u.list.values[seq_iter_count-1];

				continue;

			case bynar_dict:
				if (seq_iter_count == 0) {

					total += 1; /* 'd' */

					if (value->u.dict.length == 0) {
						total += 1; /* ';' */
						break;
					}
				}

				if (seq_iter_count == value->u.dict.length * 2) {
					total += 1; /* ';' */
					seq_iter_count = 0; /* clean up iter */
					break;
				}

				seq_iter_count += 1;

				if (seq_iter_count & 1)
					value = value->u.dict.values[seq_iter_count/2].key;
				else
					value = value->u.dict.values[(seq_iter_count-1)/2].value;

				continue;

			default:
				printf("!*!*!defaulting in counting switch (%i)\n", value->type); // TODO remove this
				break;
		}

		value = value->parent;
	}

	return total;
}

/** char * buffer to a `bynar_value` */
bynar_value * bynar_deserialize(char * buf, size_t len, char *error_buf) {


	bynar_value * current = NULL;
	bynar_value * new;

	char * found;
	size_t end = 0;


	bynar_int_t working = 1;

	for(int i=0; i<len; ++i) {
		char c = buf[i];

		switch (c) {
			case 'i':

				found = strchr(&buf[i], ';');

				if (!found) {
					sprintf(error_buf, "Expected `;` near %i to end int", i);
					return NULL;
				}

				end = found - buf;

				working = buf[++i] - '0';
				while(i < end-1) {
					working = (working * 10) + (buf[++i] - '0');
				}

				i+=1;

				new = bynar_int_new(working);

				break;

			case 'f':
				found = strchr(&buf[i], ';');

				if (!found) {
					sprintf(error_buf, "Expected `;` near %i to end float", i);
					return NULL;
				}
				i+=1;

				char * next;

				new = bynar_float_new(strtold(&buf[i], &next));

				i += (next-buf-2); /* move to next item after ';' */

				break;

			case 's':
				found = strchr(&buf[i], ':');

				if (!found) {
					sprintf(error_buf, "Expected `:` after %i to start string", i);
					return NULL;
				}

				end = found - buf;

				working = buf[++i] - '0';
				while(i < end-1) {
					working = (working * 10) + (buf[++i] - '0');
				}
				i+=2;

				new = bynar_string_new(&buf[i], working);

				i += working - 1;

				break;

			case 'l':
				new = bynar_list_new(0);
				break;

			case 'd':
				new = bynar_dict_new(0);
				break;

			case 'T':
				new = bynar_bool_new(1);
				break;
			case 'F':
				new = bynar_bool_new(0);
				break;
			case '\x00':
				new = bynar_null_new();
				break;
			case ';':
				if (current->parent) {
					((bynar_sequence_builder *) current)->iter_count = 0;
					current = current->parent;
				}
				break;
			default:
				printf("unknown type to serialize to (%c)at %i\n", c, i);
				break;
		} // end switch


		if (current && new) {


			if (current->type == bynar_list) {

				bynar_list_append(current, new);

			}
			else
			if (current->type == bynar_dict) {

				size_t dict_iter = ((bynar_sequence_builder *) current)->iter_count;

				new->parent = current;

				if (dict_iter & 1) { // value

					current->u.dict.values[(dict_iter-1)/2].value = new;

				} else { // key
					/* create a null:null entry as temp */
					bynar_dict_push(current, bynar_null_new(), bynar_null_new());

					current->u.dict.values[(dict_iter)/2].key = new;
				}

				((bynar_sequence_builder *) current)->iter_count += 1;

			}

			if (new->type == bynar_list || new->type == bynar_dict) {
				current = new;
			}

			new = NULL;

			continue;
		}

		if (new)
			current = new;


	} // end for

	return current;
};

/** Frees the memory of a `bynar_value` */
void bynar_free(bynar_value * value) {

	bynar_value * current_value; /* per itter: used to free the upper struct (eg list) or standard type (eg int)*/

	while (value) {
		switch (value->type) {

			case bynar_string:

				free(value->u.string.pointer);
				break;

			case bynar_list:

				if (value->u.list.length == 0) {
					free(value->u.list.values);
					break; /* done with list */
				}


				/* move to next value in list while lowering length */
				value = value->u.list.values[ -- value->u.list.length ];

				continue;
				// value = value->parent; done auto as last while() action

			case bynar_dict:
				/* seq_iter_count ==> ((bynar_sequence_builder *) value)->iter_count
				in this function (unlike others) `seq_iter_count` is used like a bool
				swapping between key and value freeing by using its even-ness.
				 */

				if (value->u.dict.length == 0) {
					// printf("done freeing dict\n");
					free(value->u.dict.values);
					break;
				}

				if (seq_iter_count & 1) { // odd

					seq_iter_count = 2;
					value->u.dict.length -= 1;

					// dont need to -1 from index because length is already subtracted
					value = value->u.dict.values[value->u.dict.length].value;

				} else { // even
					// printf("freeing key at i=%i\n", value->u.dict.length-1);

					seq_iter_count = 1;

					value = value->u.dict.values[value->u.dict.length-1].key;
				}

				continue;

			default:
				break;
		}

		current_value = value;
		value = value->parent;
		free(current_value); /* free top level pointer */
	}
}

/** Same as strchr, but skips over chars in bynar serialized string
ex: s3f()), first ')' ignored
helps avoid injection
*/
char * strchr_bynar_safe(const char * s, char c) {
	int str_end = 0;
	while(1) {

		if (*s == 's') {
			char * next;
			str_end = strtol(++s, &next, 10) + 1;
			s = next + str_end;
		}

		if (*s == c)
			return (char *)s;

		if (*s == 0)
			return 0;

		s++;
	}
}


#endif
