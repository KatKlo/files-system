#pragma once

#include <stdbool.h>
#include "HashMap.h"

typedef struct Node Node;

Node *node_new(Node *);

int node_free(Node *, bool);

HashMap *get_sub_folders(Node *);

Node * get_child(Node *, const char *);

void change_parent(Node *, Node *);

Node *find_node(const char *, Node *, bool);

Node *find_parent(const char *, char *, Node *, bool);

void decrease_counter(Node *, Node *);

void node_get_as_reader(Node *);

void node_get_as_writer(Node *);

void node_get_as_remover(Node *node);

void node_free_as_reader(Node *);

void node_free_as_writer(Node *);