#include <pthread.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <string.h>
#include <assert.h>
#include "tree_utils.h"
#include "HashMap.h"
#include "err.h"
#include "path_utils.h"

struct Vector {
    Node **values;
    size_t capacity;
    size_t size;
};

struct Node {
    HashMap *subfolders;

    pthread_mutex_t* lock;
    pthread_cond_t *readers;
    pthread_cond_t *writers;
    pthread_cond_t *removers;

    int readers_count, writers_count;
    int readers_wait, writers_wait, removers_wait;
    int change; // 0 - no one, 1 - readers, 2 - writer, 3 - removers
    int readers_to_wake; // how many readers to wake
    int counter;

    Vector *path;
};

void *safe_malloc(size_t size) {
    void *res = malloc(size);

    if (res == NULL)
        syserr("malloc failed");

    return res;
}

static void safe_realloc(Node ***pointer, size_t new_size) {
    *pointer = realloc(*pointer, new_size);

    if (*pointer == NULL)
        syserr("realloc failed");
}

static Vector *vector_new() {
    Vector *new_vector = (Vector *) safe_malloc(sizeof(Vector));

    new_vector->values = NULL;
    new_vector->capacity = 0;
    new_vector->size = 0;

    return new_vector;
}

static void vector_add_node(Vector *vector, Node *value) {
    if (vector->size == vector->capacity) {
        vector->capacity = vector->capacity * 2 + 1;
        safe_realloc(&vector->values, vector->capacity * sizeof(Node *));
    }

    vector->values[vector->size++] = value;
}

static void vector_add_vector(Vector *vector, Vector *to_add) {
    if (to_add == NULL)
        return;

    bool need_realloc = false;

    while (vector->size + to_add->size > vector->capacity) {
        need_realloc = true;
        vector->capacity = vector->capacity * 2 + 1;
    }

    if (need_realloc)
        safe_realloc(&vector->values, vector->capacity * sizeof(Node *));

    for (int i = 0; i < to_add->size; i++) {
        vector->values[vector->size++] = to_add->values[i];
    }
}

void vector_change(Vector *vector, Vector *to_change, Node *value) {
    if (to_change == NULL)
        return;

    bool need_realloc = false;

    while (to_change->size + 1 > vector->capacity) {
        need_realloc = true;
        vector->capacity = vector->capacity * 2 + 1;
    }

    if (need_realloc)
        safe_realloc(&vector->values, vector->capacity * sizeof(Node *));

    vector->size = 0;

    for (int i = 0; i < to_change->size; i++) {
        vector->values[vector->size++] = to_change->values[i];
    }

    vector->values[vector->size++] = value;
}

static void vector_free(Vector *to_free) {
    free(to_free->values);
    free(to_free);
}

static void safe_mutex_init(pthread_mutex_t **mutex) {
    *mutex = (pthread_mutex_t *) safe_malloc(sizeof(pthread_mutex_t));

    if (pthread_mutex_init(*mutex, 0) != 0)
        syserr("mutex init failed");
}

static void safe_cond_init(pthread_cond_t **cond) {
    *cond = (pthread_cond_t *) safe_malloc(sizeof(pthread_cond_t));

    if (pthread_cond_init(*cond, 0) != 0)
        syserr("cond init failed");
}

static void safe_mutex_free(pthread_mutex_t *mutex) {
    if (pthread_mutex_destroy(mutex))
        syserr("mutex destroy failed");

    free(mutex);
}

static void safe_cond_free(pthread_cond_t *cond) {
    if (pthread_cond_destroy(cond) != 0)
        syserr("cond destroy failed");

    free(cond);
}

Node *node_new(Vector *parent_path) {
    Node *new_node = (Node *) safe_malloc(sizeof(Node));

    new_node->subfolders = hmap_new();

    if (!new_node->subfolders)
        syserr("creating new hmap failed");

    new_node->path = vector_new();

    if (!new_node->path)
        syserr("creating new vector failed");

    vector_add_vector(new_node->path, parent_path);
    vector_add_node(new_node->path, new_node);

    safe_mutex_init(&new_node->lock);
    safe_cond_init(&new_node->readers);
    safe_cond_init(&new_node->writers);
    safe_cond_init(&new_node->removers);

    new_node->readers_count = 0;
    new_node->writers_count = 0;
    new_node->readers_wait = 0;
    new_node->writers_wait = 0;
    new_node->removers_wait = 0;
    new_node->readers_to_wake = 0;
    new_node->change = 0;
    new_node->counter = 0;

    return new_node;
}

HashMap *get_subfolders(Node *node) {
    return node->subfolders;
}

Vector *get_nodes_path(Node *node) {
    return node->path;
}

static void signal_with_change(Node *node, pthread_cond_t *who, int new_change) {
    node->change = new_change;

    if (pthread_cond_signal(who) != 0)
        syserr ("cond signal failed");
}

void decrease_counter(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->counter--;

    if (node->counter + node->readers_wait + node->writers_wait + node->readers_count + node->writers_count + node->change == 0)
        if (node->removers_wait > 0)
            signal_with_change(node, node->removers, 3);

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

static void increase_counter(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->counter++;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

void decrease_counter_path(Vector *nodes_path, Node *begin) {
    if (!nodes_path)
        return;

    int i = 0;

    if (begin != NULL)
        while (nodes_path->values[i] != begin)
            i++;

    i++;

    for (; i < nodes_path->size; i++) {
        decrease_counter(nodes_path->values[i]);
    }
}

void node_get_as_reader(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    while (node->writers_count + node->writers_wait + node->change > 0) {
        node->readers_wait++;

        if (pthread_cond_wait(node->readers, node->lock) != 0)
            syserr("cond wait failed");

        node->readers_wait--;

        if (node->change == 1) {
            node->readers_to_wake--;
            break;
        }
    }

    node->readers_count++;

    if(node->readers_to_wake > 0)
        signal_with_change(node, node->readers, 1);
    else
        node->change = 0;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

void node_get_as_writer(Node * node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    while (node->readers_count + node->writers_count + node->change > 0) {
        node->writers_wait++;

        if (pthread_cond_wait(node->writers, node->lock) != 0)
            syserr("cond wait failed");

        node->writers_wait--;

        if (node->change == 2)
            node->change = 0;
    }

    node->writers_count++;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

void node_get_as_remover(Node * node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    while (node->readers_count + node->writers_count + node->readers_wait + node->writers_wait + node->change + node->counter > 0) {
        node->removers_wait++;

        if (pthread_cond_wait(node->removers, node->lock) != 0)
            syserr("cond wait failed");

        node->removers_wait--;

        if (node->change == 3)
            node->change = 0;
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

void node_free_as_reader(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->readers_count--;

    if(node->readers_count == 0 && node->readers_to_wake == 0) {
        if(node->writers_wait > 0) {
            signal_with_change(node, node->writers, 2);
        } else if(node->readers_wait > 0) {
            node->readers_to_wake = node->readers_wait;
            signal_with_change(node, node->readers, 1);
        } else if (node->removers_wait > 0 && node->counter == 0) {
            signal_with_change(node, node->removers, 3);
        }
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");

}

void node_free_as_writer(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->writers_count--;

    if(node->readers_wait > 0) {
        node->readers_to_wake = node->readers_wait;
        signal_with_change(node,node->readers, 1);
    } else if(node->writers_wait > 0) {
        signal_with_change(node, node->writers, 2);
    } else if (node->removers_wait > 0 && node->counter == 0) {
        signal_with_change(node, node->removers, 3);
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");

}

int node_free(Node *node, bool delete_all) {
    node_get_as_remover(node);

    if (!delete_all && hmap_size(node->subfolders) > 0) {
        return ENOTEMPTY;
    }

    const char *key;
    void *value;

    HashMapIterator it = hmap_iterator(node->subfolders);
    while (hmap_next(node->subfolders, &it, &key, &value))
        node_free((Node *) value, delete_all);

    hmap_free(node->subfolders);
    vector_free(node->path);

    safe_mutex_free(node->lock);
    safe_cond_free(node->readers);
    safe_cond_free(node->writers);
    safe_cond_free(node->removers);

    free(node);

    return 0;
}

Node *find_node(const char *path, Node *begin, bool begin_rw_locked) {
    Node *node = begin;
    void *maybe_node;

    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char *subpath = path;

    while ((subpath = split_path(subpath, component))) {
        if (node != begin || !begin_rw_locked)
            node_get_as_reader(node);

        maybe_node = hmap_get(node->subfolders, component);

        if (!maybe_node) {
            decrease_counter_path(node->path, begin);

            if (node != begin || !begin_rw_locked)
                node_free_as_reader(node);

            return NULL;
        }

        Node *old_node = node;
        node = (Node *) maybe_node;
        increase_counter(node);

        if (old_node != begin || !begin_rw_locked)
            node_free_as_reader(old_node);
    }

    return node;
}

Node *find_parent(const char *path, char *subfolder_name, Node *begin, bool own) {
    char *subpath = make_path_to_parent(path, subfolder_name);

    if (!subpath)
        return NULL;

    Node * result = find_node(subpath, begin, own);

    free(subpath);

    return result;
}

Node * get_child(Node *parent, const char *name) {
    Node *sth = hmap_get(parent->subfolders, name);

    if (sth == NULL)
        return NULL;

    return (Node *) sth;
}

void change_nodes_paths(Node *node, Node *new_parent) {
    node_get_as_reader(node);

    vector_change(node->path, new_parent->path, node);

    const char *key;
    void *value;

    HashMapIterator it = hmap_iterator(node->subfolders);
    while (hmap_next(node->subfolders, &it, &key, &value))
        change_nodes_paths((Node *) value, node);

    node_free_as_reader(node);

}

char *find_both_parent(const char *source, const char *target, char **new_source, char **new_target) {
    int i = 0, j = 0, last_ok = 0;
    char component[MAX_FOLDER_NAME_LENGTH + 1];
    char *source_parent = make_path_to_parent(source, component);
    char *target_parent = make_path_to_parent(target, component);

    int source_size = strlen(source), target_size = strlen(target);
    int source_parent_size = strlen(source_parent), target_parent_size = strlen(target_parent);

    while (i < source_parent_size && j < target_parent_size) {
        if (source_parent[i] != target_parent[j])
            break;

        if (source_parent[i] == '/')
            last_ok = i;
        i++;
        j++;
    }

    *new_source = malloc((source_size - last_ok + 1) * sizeof(char));
    *new_target = malloc((target_size - last_ok + 1) * sizeof(char));
    char *found_parent = malloc((last_ok + 2) * sizeof(char));

    for (int k = 0; k <= last_ok; k++) {
        found_parent[k] = source[k];
    }
    found_parent[last_ok + 1] = '\0';

    for (int k = last_ok; k < source_size + 1; k++) {
        (*new_source)[k - last_ok] = source[k];
    }

    for (int k = last_ok; k < target_size + 1; k++) {
        (*new_target)[k - last_ok] = target[k];
    }

    free(source_parent);
    free(target_parent);

    return found_parent;
}
