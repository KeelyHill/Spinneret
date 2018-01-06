/** Copyright (C) 2016 Keely Hill */

#include "stdio.h"
#include <string.h>

#include "bynar.c"
#include "broadcast.h"

#include "b64.c"

/* util */
const int i = 1; // used to determine native engian
#define is_bigendian() ( (*(char*)&i) == 0 )

#define MAX_PAYLOAD_CAN_HANDLE 0xffff
// payload max = 65535 = xffff

#define BROADCAST_NONCE_ID_SIZE 4

void str_cpy_terminated(char *restrict dst, const char *restrict src, size_t n) {
	strncpy(dst, src, n);
	dst[n] = '\0'; // null terminates TODO hack check this is okay with Josh/Randy
}

/** This needs to be supplied at compile */
extern void randombytes(unsigned char *, unsigned long long);


/* struct that reprents self (as spinneret node) */

struct this_node {
	char * addr;

	/* do_action(action_name, bynar_list_of_args) */
	bynar_value * (*do_action_ptr)(char * action_name, bynar_value * list_of_args);

	/* get_property_named_ptr(property_name-null terminated)*/
	bynar_value * (*get_property_named_ptr)(char * property_name);

	/* Random Number Generator */ // DEPRECATED probably, instead use `extern randombytes`
	// int * (*RNG)(unsigned char * ptr, unsigned int length);

	unsigned char private_key[32];
	unsigned char public_key[32];

	unsigned char signing_key[32]; /* private */
	unsigned char verify_key[32]; /* public */

	bynar_value * secure_groups; /* dict, [group name]:[secret key] */
	bynar_value * joined_groups; /* list, just standard groups */
} me_node;

void init_this_node() {
	me_node.secure_groups = bynar_dict_new(0);
	// me_node.joined_groups = bynar_list_new(0);
}


int handle_raw_broadcast(const char *raw_data, transmittable_broadcast_t *tb);
int process_plain_broadcast(const char * plaindata, transmittable_broadcast_t *tb, unsigned short len);
int process_payload(broadcast_t *parsed, transmittable_broadcast_t *tb);

void encode_broadcast(broadcast_t *b /* to build */, transmittable_broadcast_t *tb /*result*/);

// int (* process_payload_prt)(broadcast_t *, transmittable_broadcast_t *) = &process_payload; // IDEA an option to have this be overridable

int handle_raw_broadcast(const char *raw_data, transmittable_broadcast_t *tb) {

	if (raw_data[0] == '\x01') {

		unsigned char endian[2];
		if (is_bigendian()) { endian[0] = raw_data[2]; endian[1] = raw_data[3]; }
		else {endian[0] = raw_data[3]; endian[1] = raw_data[2];}

		unsigned short len =  *(unsigned short *) endian;

		if (len > MAX_PAYLOAD_CAN_HANDLE) {
			// for a small device that limited ram
			printf("Payload to large (%hu) for this device to process./n", len);
			return -2;
		}

		switch (raw_data[1]) {
			case '\x00': // non-encyted testing handle

				return process_plain_broadcast(raw_data+=4, tb, len);

				// return 1;
			case '\x01': // chacha is a stream cipher and can be decrypted in chunk on the way in, i.e. read the size from first 4 bytes, then decypt directly into buffer
				break;
			case '\x05': // discovery
				break;
			// default:
			// 	return 0;
		}

	}
	printf("Unknown raw broadcast start (version and handle)\n");
	return -1;
}



/*

*/
int process_plain_broadcast(const char * plaindata, transmittable_broadcast_t *tb, unsigned short len) {

	const char *buf = plaindata;

	char vnonce[7];
	bcast_kind kind;
	char to[32];
	char from[32];

	int num = strchr(buf, '|') - buf;
	str_cpy_terminated(vnonce, buf, num);
	buf+=num+1;
	// buf+=7; // skip the version and nonce


	switch (*(buf+2)) { // the 3rd letter is unique
		case 'Q':
			kind = REQ;
			break;
		case 'S':
			kind = RESP;
			break;
		case 'N':
			kind = ANNC;
			break;
	}

	buf = strchr(buf,'|') + 1; // go to next section

	num = strchr(buf, '|') - buf; // to
	str_cpy_terminated(to, buf, num);
	buf+=num+1;

	num = strchr(buf, '|') - buf; // from
	str_cpy_terminated(from, buf, num);
	buf+=num+1;


	short one_more_section = 0; // false

	num = strchr(buf, '|') - buf;
	if (num<=0) num = &plaindata[len] - buf;
	else one_more_section = 1; // true

	// TODO deal with last section if there and based on kind


	/* payload decode b64 */

	size_t max_norm_len = 3*(num/4); // max size needed based on padded length
	// IDEA make a more precise calculation
	printf("max norm len = %zu\n", max_norm_len);

	// unsigned char payload[max_norm_len];
	unsigned char * payload = (unsigned char *) malloc(sizeof(char) * max_norm_len);
	size_t norm_len = max_norm_len;

	if (base64_decode((char*)buf, num, payload, &norm_len)) {
		// failed
		printf("FAILED b64 conversion\n");
	}

	// TODO decrypt payload as needed, update len too


	broadcast_t parsed_broadcast = {
		.kind = kind,
		.to = to,
		.from = from,
		.payload = (char *)payload,
		.payload_len = norm_len,
		.annc_group = NULL // TODO deal with this from above
	};
	// print_broadcast(&parsed_broadcast);

	process_payload(&parsed_broadcast, tb);

	return 1;
}




/**

returns: response dict as bynar_value *
*/
bynar_value * process_req_payload(broadcast_t *parsed) {

	char *buf = parsed->payload;

	bynar_value * resp_dict = bynar_dict_new(1);

	for (int i=0; i < parsed->payload_len; i++) {

		bynar_value * this_key;
		bynar_value * this_value;

		if (buf[i] == '^') { /* is action */

			int name_len = strchr(&buf[i], '(') - buf - i;

			char act_name[name_len];
			str_cpy_terminated(act_name, &buf[i], name_len);

			bynar_value *args_list;

			i += name_len; /* skip to '(' */

			int args_len = strchr_bynar_safe(&buf[i], ')') - buf - i;

			if (args_len == 1) { /* i.e. 'fn()' */
				args_list = NULL;
			} else {
				buf[i] = 'l'; /* (...) -> l...; for easy decoding */
				buf[args_len+i] = ';';

				args_list = bynar_deserialize(&buf[i], args_len+1, NULL);
			}

			i += args_len;

			/* callback, without `^` at start of name */
			this_value = (* me_node.do_action_ptr)(act_name+1, args_list); // TODO how does this return in case of run error?

			this_key = bynar_string_new(act_name, name_len);

			printf("act name%s\n", act_name);

		} else { /* is prop */

			// len of prop str to compare
			int upto = strchr(&buf[i], ',') - buf;
			if (upto < 0) upto=parsed->payload_len-i;

			this_key = bynar_string_new(&buf[i], upto);

			this_value = (* me_node.get_property_named_ptr)(this_key->u.string.pointer);

			// TODO how to handle '\x15' error byte (see RESP spec)
			i+=upto;
		}

		/* add to dict */

		printf(" d %s:%s\n", this_key->u.string.pointer, this_value->u.string.pointer);
		bynar_dict_push(resp_dict, this_key, this_value);

	}

	return resp_dict;
}

int process_resp_payload(broadcast_t *parsed, transmittable_broadcast_t *tb) {
	return -1;
}

int process_annc_payload(broadcast_t *parsed, transmittable_broadcast_t *tb) {
	return -1;
}

int process_payload(broadcast_t *parsed, transmittable_broadcast_t *tb) {

	switch (parsed->kind) {
		case REQ:
			{

				bynar_value * resp_dict = process_req_payload(parsed);

				size_t serialized_size = bynar_get_serialized_size(resp_dict);
				char * payload_serialized = malloc(serialized_size); /*sizeof(char)==1*/
				// TODO may be able to use ^ char[serialized_size] and not malloc, if contiuning in stack (and not needing this var after func returns)

				bynar_serialize(payload_serialized, resp_dict);


				// TODO fix to comply to the need of an ANNC to a group/all


				broadcast_t brocast_to_build = {RESP, parsed->from, parsed->to, payload_serialized, (uint16_t)serialized_size, NULL};

				encode_broadcast(&brocast_to_build, tb);

				// TODO encrypt `payload_serialized` accordingly


			}

			break;
		case RESP:
			return process_resp_payload(parsed, tb);
			break;
		case ANNC:
			return process_annc_payload(parsed, tb);
			break;
	}
	return 0;
}


/** puts str chars onto buf, buf allocation assumed
	returns: pointer to next char (char after it ended on)
 */

char * buffer_append_str(char *buf, char *str) {

	while (*str) {
		*buf++ = *str++;
	}

	return buf;
}

char * buffer_append_str_len(char *buf /* to */, char *str, size_t len) {

	for (size_t i=0; i<len; i++) {
		*buf++ = str[i];
	}

	return buf;
}

void encode_broadcast(broadcast_t *b /* to build */, transmittable_broadcast_t *tb /*result*/) {

	/* determin how to encrypt payload */

	char * encrypted_payload = ""; /* may not be encrypted */
	size_t encrypted_payload_len = b->payload_len + 8; // TODO replace 8 with #define

	if (b->to[0] == '#') { /* to secure group */

		const char * group_name = b->to + 1;
		bynar_value * group_key = NULL;

		group_key = bynar_dict_get_string(me_node.secure_groups, group_name);

		if (group_key != NULL) {

			encrypted_payload = (char *) malloc(b->payload_len /* + size of chacha nonce */);
			// b->payload_len += size of chacha nonce

			// TODO do cipher, prepend nonce
			// TODO replace 8 with #define
			unsigned char nonce[8];
			randombytes(&nonce[0], 8);

			/* prepend nonce */
			buffer_append_str_len(encrypted_payload, (char *)&nonce, 8);
			encrypted_payload += 8; /* move pointer to start of encrypted data */

			/* encrypt into `encrypted_payload` */
			// crypto_chacha20_stream_xor(encrypted_payload, b->payload, b->payload_len, nonce, (unsigned char *)group_key.pointer);
			buffer_append_str_len(encrypted_payload, b->payload, b->payload_len); // temp
			encrypted_payload -= 8; /* move back to start of nonce */


		} else {
			printf("not a member of grou\n");
			// TODO deal with error, not a member of group
		}



	} else if (b->payload[0] != '*') { /* to individual */

	} else { // no encyption
		// encrypted_payload = b->payload;
		buffer_append_str_len(encrypted_payload, b->payload, b->payload_len);
	}

	free(b->payload); /* dont need it anymore, real payload in `encrypted_payload` */

	/* PLAIN ENCODE encode plain broadcast into tb->data buffer */

	char * out = tb->data;

	*out++ = 0x00;
	*out++ = 0x01;

	/* nonce */
	randombytes((unsigned char *)out, BROADCAST_NONCE_ID_SIZE);
	out += BROADCAST_NONCE_ID_SIZE;

	*out++ = '|';

	switch (b->kind) {
		case REQ:
			out = buffer_append_str(out, "REQ");
			break;
		case RESP:
			out = buffer_append_str(out, "RESP");
			break;
		case ANNC:
			out = buffer_append_str(out, "ANNC");
			break;
	}

	*out++ = '|';

	out = buffer_append_str(out, b->to);

	*out++ = '|';

	out = buffer_append_str(out, b->from);

	*out++ = '|';

	switch (b->kind) {
		case REQ:
			if (!b->annc_group)
				b->annc_group = "n";

			/* [payload]|[annc_group] */
			out = buffer_append_str_len(out, encrypted_payload, encrypted_payload_len);

			*out++ = '|';

			out = buffer_append_str(out, b->annc_group);

			break;
		case RESP:
			if (!b->resp_code)
				b->resp_code = "ACK";

			/* [code|[payload] */
			out = buffer_append_str(out, b->resp_code);

			*out++ = '|';

			out = buffer_append_str_len(out, encrypted_payload, encrypted_payload_len);
			break;
		case ANNC:
			out = buffer_append_str_len(out, encrypted_payload, encrypted_payload_len);
			break;
	}

	tb->data_len = out - tb->data;

	print_escaped(tb->data, tb->data_len);

	/* encypt and sign plain broadcast (full, not payload) accordingly */

	// TODO

}


/** High level outline of logic for a barebones implementaion (top-down flow)

- decrypt
- parse to determine to, from, kind, payload, etc
- Based on 'kind':
	REQ:
		- check for variable names in payload
		- check for actions in payload
		- run action/respond with variable value
	ANNC
		- probably ignore, assuming low RAM and non-volitle (i.e. barebones)
	RESP
		- match to request pending for ACK or whatever
		- else ignore

- Respond accordingly
- Route property if can

**/
