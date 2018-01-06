#ifndef _BROADCAST_H_
#define _BROADCAST_H_


typedef enum bcast_kind {REQ, RESP, ANNC} bcast_kind;
typedef enum bcast_resp_code {x, xx, xxx, unknown} bcast_resp_code;

typedef struct transmittable_broadcast {
	char *data;
	uint16_t data_len;
	char *to;
} transmittable_broadcast_t;


typedef struct broadcast { // in came broadcast
	bcast_kind kind;
	char *to;
	char *from;
	char *payload;
	uint16_t payload_len;

	char *annc_group; /* only for REQ, can be null */
	char *resp_code; /* only for RESP */
} broadcast_t;

void print_escaped(char * str, uint16_t len) {

	for (uint16_t i=0; i<len; i++) {

		if (str[i] < 33 || str[i] > 126) {
			printf("\\x%02x", (unsigned char)str[i]);
		} else {
			printf("%c", str[i]);
		}
	}
	printf("\n");
}

void print_broadcast(broadcast_t *b) {
	printf("kind:%u\n", b->kind);
	printf("to:%s\n", b->to);
	printf("from:%s\n", b->from);
	print_escaped(b->payload, b->payload_len);
}




int serialize_plain_broadcast(char * out_buf, broadcast_t * b) {





	return 0;
}


#endif
