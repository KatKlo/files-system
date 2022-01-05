#pragma once

#include <stdbool.h>
#include "HashMap.h"

#define ENOTALLOW -1

typedef struct Node Node;

typedef struct Vector Vector;

void *safe_malloc(size_t);

Node *node_new(Vector *);

int node_free(Node *, bool);

void change_nodes_paths(Node *, Node *);

HashMap *get_subfolders(Node *);

Vector *get_nodes_path(Node *);

Node *find_node(const char *, Node *, bool);

Node *find_parent(const char *, char *, Node *, bool);

void decrease_counter(Node *node);

void decrease_counter_path(Vector *, Node *);

void node_get_as_reader(Node *);

void node_get_as_writer(Node *);

void node_get_as_remover(Node *node);

void node_free_as_reader(Node *);

void node_free_as_writer(Node *);

Node * get_child(Node *parent, const char *name);

char *find_both_parent(const char *, const char *, char **, char **);