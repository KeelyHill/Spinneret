#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "bynar.c"

int prims_tests() {
	char * buf = malloc(4);

	bynar_value * tester;

	/* int */
	tester = bynar_int_new(42);
	bynar_serialize(buf, tester);

	printf("%s\n", buf);

	assert(!strcmp(buf, "i42;"));


	/* float */
	tester = bynar_float_new(1.23);
	bynar_serialize(buf, tester);

	printf("%s\n", buf);

	assert(!strcmp(buf, "f1.23;"));

	buf[1] = '\0'; // clear buffer

	/* bool */
	tester = bynar_bool_new(1);
	bynar_serialize(buf, tester);

	printf("%s\n", buf);

	assert(!strcmp(buf, "T"));

	/* Null */
	tester = bynar_null_new();
	bynar_serialize(buf, tester);

	printf("%s\n", buf);

	assert(!strcmp(buf, "\x00"));

	bynar_free(tester); /* <--- this is a test too */

	free(buf);
	return 1;
}

int string_test() {

	char * buf = malloc(50);

	bynar_value * mystring = bynar_string_new("Hello, world", 12);

	bynar_serialize(buf, mystring);

	printf("%s\n", buf);

	assert(!strcmp(buf, "s12:Hello, world"));

	bynar_free(mystring); /* <--- this is a test too */

	/* with no copy */
	char mystringval[6] = "Pizza\0";

	mystring = bynar_string_new_nocopy(mystringval, 6);

	bynar_serialize(buf, mystring);

	printf("%s\n", buf);

	assert(!strcmp(buf, "s6:Pizza"));

	free(buf);
	return 1;
}

int list_test() {

	char * buf = malloc(20);

	bynar_value * mylist = bynar_list_new(2);

	bynar_serialize(buf, mylist);
	assert(!strcmp(buf, "l;")); // empty list

	bynar_list_append(mylist, bynar_int_new(42));
	bynar_list_append(mylist, bynar_int_new(64));
	bynar_list_append(mylist, bynar_string_new("uppers", 6));

	// printf("%lli\n", mylist->u.list.values[1]->u.integer);

	bynar_serialize(buf, mylist);
	buf[19] = 0;
	printf("%s\n", buf);

	assert(!strcmp(buf, "li42;i64;s6:uppers;"));

	bynar_free(mylist); /* <--- this is a test too */

	free(buf);
	return 1;
}

int dict_test() {

	char * buf = malloc(37);

	bynar_value * mydict = bynar_dict_new(0);

	bynar_value * innerlist = bynar_list_new(3);
	bynar_list_append(innerlist, bynar_float_new(4.2));
	bynar_list_append(innerlist, bynar_float_new(3.4));
	bynar_list_append(innerlist, bynar_float_new(5.6));

	bynar_dict_push(mydict, bynar_string_new("a",1), bynar_int_new(7)); //<-- should get overwritten
	bynar_dict_push(mydict, bynar_string_new("a",1), bynar_int_new(11));
	bynar_dict_push(mydict, bynar_string_new("b",1), bynar_int_new(2));
	bynar_dict_push(mydict, bynar_string_new("c",1), innerlist);

	bynar_serialize(buf, mydict);

	assert(!strcmp(buf, "ds1:ai11;s1:bi2;s1:clf4.2;f3.4;f5.6;;;"));

	printf("got you from dict: %lli\n", bynar_dict_get_string(mydict, "a")->u.integer);

	printf("%s\n", buf);

	printf("\n");
	bynar_free(mydict); /* <--- this is a test too, it does the inner too */

	free(buf);
	return 1;
}

int deserialize_test_overview() {

	char error_buf[100]; error_buf[0] = 0;

	char in[] = "lf3.21;di42;i17;;s3:Hi!;";
	size_t len = strlen(in);

	bynar_value *deed = bynar_deserialize(in, len, error_buf);

	size_t se_count = bynar_get_serialized_size(deed);

	assert(se_count == 24);

	char outer[se_count];
	bynar_serialize(outer, deed);

	assert(!strncmp(outer, in, 24));

	bynar_free(deed); /* <--- this is a test too */

	// printf("outer: %s\n", outer);
	// printf("error: %s\n", error_buf);

	return 1;
}

int main () {

	int prim_success = prims_tests();
	int string_success = string_test();
	int list_success = list_test();
	int dict_success = dict_test();

	int deserialize_test_sucess = deserialize_test_overview();

	int success = prim_success & string_success & list_success & dict_success & deserialize_test_sucess;

	printf("\n%s\n", success ? "SUCCESS" : "FAILURE, a test failed");


	return 0;
}
