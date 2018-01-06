
#include "barebone-spinneret-node.c"

#include <time.h>
clock_t start, stop;
double duration;

// #include "randombytes/devurandom.h"


bynar_value * do_action(char * name, bynar_value * args_list) {


	printf("This is where the action would be done. (name=%s)\n", name);

	printf("arg[0] = '%s'\n", args_list->u.list.values[0]->u.string.pointer);

	return bynar_null_new(); // TODO this is temp
}

bynar_value * get_property_named(char * name) {

	if (strcmp(name, "state") == 0) {
		printf("state match\n");

	}

	if (strcmp(name, "test") == 0) {
		printf("test prop match\n");
	}

	return bynar_null_new();
}

int main(void) {
    printf("\n___\n\n");
	start=clock();

	init_this_node();
	me_node.addr = "tofoo";
	me_node.do_action_ptr = &do_action;
	me_node.get_property_named_ptr = &get_property_named;


	bynar_value * fake_key = bynar_string_new("1234567890qwertyuiopasdfghjklzxc", 32);
	bynar_dict_push_string_key(me_node.secure_groups, "frmbar", fake_key);

	transmittable_broadcast_t tb;
	tb.data = malloc(100);

	handle_raw_broadcast("\x01\x00\x00\x39nanonc|REQ|tofoo|#frmbar|c3RhdGUsXmZ1bmMoczQ6KGhpKSk=", &tb);

	// printf("tb.data= %s\n", tb.data);

	//free(tb.data);


	stop=clock();
	printf("\nprocess time: %f s\n", (float)(stop-start)/CLOCKS_PER_SEC);

	return 0;
}
