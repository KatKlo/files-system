#pragma once

#include <stdbool.h>
#include "HashMap.h"

#define ENOTALLOW -1

typedef struct Node Node;

struct Node {
    HashMap *sub_folders;
    pthread_mutex_t* lock;
    pthread_cond_t *readers;
    pthread_cond_t *writers;
    pthread_cond_t *remove;
    int rcount, wcount, rwait, wwait, removewait;
    int dupa;
    int change; // 0 - no one, 1 - readers, 2 - writer, 3 - remove
    int readers_to_wake; // how many readers to wake
};

void *safe_malloc(size_t);

Node *node_new();

int node_free(Node *, bool);

Node *find_node(const char *, Node ***, size_t *, Node *, bool);

Node *find_parent(const char *, char *, Node ***, size_t *, Node *, bool);

void decrease_dupa(Node *);

void decrease_dupa_path(Node **, size_t);

void node_get_as_reader(Node *);

void node_get_as_writer(Node *);

void node_get_as_remove(Node *);

void node_free_as_reader(Node *);

void node_free_as_writer(Node *);

Node * get_child(Node *, const char *);

char *find_both_parent(const char *, const char *, char **, char **);