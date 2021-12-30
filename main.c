#include "HashMap.h"
#include "Tree.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void print_map(HashMap *map) {
    const char *key = NULL;
    void *value = NULL;
    printf("Size=%zd\n", hmap_size(map));
    HashMapIterator it = hmap_iterator(map);
    while (hmap_next(map, &it, &key, &value)) {
        printf("Key=%s Value=%p\n", key, value);
    }
    printf("\n");
}


int main(void) {
    Tree *t = tree_new();

    printf("create /a/ -> %d\n", tree_create(t, "/a/"));
    printf("%s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"));

    printf("create /b/ -> %d\n", tree_create(t, "/b/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("create /a/c/ -> %d\n", tree_create(t, "/a/c/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("create /a/d/ -> %d\n", tree_create(t, "/a/d/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("remove /a/ -> %d\n", tree_remove(t, "/a/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("move /a/c/ /b/e/ -> %d\n", tree_move(t, "/a/c/", "/b/e/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("remove /b/ -> %d\n", tree_remove(t, "/b/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("remove /a/c/ -> %d\n", tree_remove(t, "/a/c/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));

    printf("remove /a/ -> %d\n", tree_remove(t, "/a/"));
    printf("%s | %s | %s\n", tree_list(t, "/"), tree_list(t, "/a/"), tree_list(t, "/b/"));


    tree_free(t);

    return 0;
}