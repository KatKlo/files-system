#include "Node.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>

#include "err.h"
#include "HashMap.h"
#include "path_utils.h"

struct Node {
    HashMap *sub_folders;

    pthread_mutex_t *lock;
    pthread_cond_t *readers;
    pthread_cond_t *writers;
    pthread_cond_t *removers;

    size_t readers_count, writers_count;
    size_t readers_wait, writers_wait, removers_wait;
    unsigned short change; // says which group is signaled: 0 - no one, 1 - readers, 2 - writer, 3 - removers
    size_t readers_to_wake; // how many readers to wake
    size_t counter; // it counts processes in this subtree

    Node *parent; // to easy decreasing counter on path
};

void *safe_malloc(size_t size) {
    void *res = malloc(size);

    if (res == NULL)
        syserr("malloc failed");

    return res;
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

Node *node_new(Node *parent) {
    Node *new_node = (Node *) safe_malloc(sizeof(Node));

    new_node->sub_folders = hmap_new();
    if (!new_node->sub_folders)
        syserr("creating new hmap failed");

    new_node->parent = parent;

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

HashMap *get_sub_folders(Node *node) {
    return node->sub_folders;
}

// Signal given cond and set change to right value
static void signal_and_set_change(Node *node, pthread_cond_t *who_to_signal, unsigned short new_change) {
    node->change = new_change;

    if (pthread_cond_signal(who_to_signal) != 0)
        syserr("cond signal failed");
}

// Recursively decrease counter on path till end node
void decrease_counter(Node *node, Node *end) {
    if (node == NULL || node == end)
        return;

    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->counter--;
    Node *next = node->parent;

    if (node->counter + node->readers_wait + node->writers_wait
        + node->readers_count + node->writers_count + node->change == 0)
        if (node->removers_wait > 0)
            signal_and_set_change(node, node->removers, 3);

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr("unlock failed");

    decrease_counter(next, end);

}

// Increase counter on node
static void increase_counter(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->counter++;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr("unlock failed");
}

// Entry protocol before reading from node's map with sub folders.
// There can be more than one process from this group
void node_get_as_reader(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    // Waits if there's process who writes, waits to write or some group is signalled right now
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

    if (node->readers_to_wake > 0)
        signal_and_set_change(node, node->readers, 1);
    else
        node->change = 0;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr("unlock failed");
}

// Entry protocol before changing something in node's map with sub folders.
// There can be more only one process from this group
void node_get_as_writer(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    // Waits if there's process who reads, writes or some group is signalled right now
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
        syserr("unlock failed");
}

// Entry protocol before removing itself
// There can be more only one process from this group
void node_get_as_remover(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    // Waits if there's any process in its tree except this one
    while (node->readers_count + node->writers_count + node->readers_wait
            + node->writers_wait + node->change + node->counter > 0) {

        node->removers_wait++;

        if (pthread_cond_wait(node->removers, node->lock) != 0)
            syserr("cond wait failed");

        node->removers_wait--;

        if (node->change == 3)
            node->change = 0;
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr("unlock failed");
}

// End protocol after reading from node's map with sub folders
void node_free_as_reader(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->readers_count--;

    // If it's the last process from this group and any process is waiting, it'll signal it
    if (node->readers_count == 0 && node->readers_to_wake == 0) {
        if (node->writers_wait > 0) {
            signal_and_set_change(node, node->writers, 2);
        } else if (node->readers_wait > 0) {
            node->readers_to_wake = node->readers_wait;
            signal_and_set_change(node, node->readers, 1);
        } else if (node->removers_wait > 0 && node->counter == 0) {
            signal_and_set_change(node, node->removers, 3);
        }
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr("unlock failed");

}

// End protocol after changing something in node's map with sub folders.
void node_free_as_writer(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->writers_count--;

    // If any process is waiting, it'll be signalled
    if (node->readers_wait > 0) {
        node->readers_to_wake = node->readers_wait;
        signal_and_set_change(node, node->readers, 1);
    } else if (node->writers_wait > 0) {
        signal_and_set_change(node, node->writers, 2);
    } else if (node->removers_wait > 0 && node->counter == 0) {
        signal_and_set_change(node, node->removers, 3);
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr("unlock failed");

}

// Free node, before doing it will wait till every process in its tree is ended.
// If there's some sub folders, and we don't want to delete them it'll return ENOEMPTY.
int node_free(Node *node, bool delete_all) {
    node_get_as_remover(node);

    if (!delete_all && hmap_size(node->sub_folders) > 0) {
        return ENOTEMPTY;
    }

    const char *key;
    void *value;

    HashMapIterator it = hmap_iterator(node->sub_folders);
    while (hmap_next(node->sub_folders, &it, &key, &value))
        node_free((Node *) value, delete_all);

    hmap_free(node->sub_folders);

    safe_mutex_free(node->lock);
    safe_cond_free(node->readers);
    safe_cond_free(node->writers);
    safe_cond_free(node->removers);

    free(node);

    return 0;
}

// Search for node given by path.
// Make sure that no one will remove or move returned node.
Node *find_node(const char *path, Node *begin, bool begin_rw_locked) {
    Node *node = begin;
    void *maybe_node;
    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char *subpath = path;

    while ((subpath = split_path(subpath, component))) {
        if (node != begin || !begin_rw_locked)
            node_get_as_reader(node);

        maybe_node = hmap_get(node->sub_folders, component);

        if (!maybe_node) {
            decrease_counter(node, begin);

            if (node != begin || !begin_rw_locked)
                node_free_as_reader(node);

            return NULL;
        }

        Node *old_node = node;
        node = (Node *) maybe_node;

        // Before freeing current node as reader we make sure that no process
        // will remove or move the next node we're going to
        increase_counter(node);

        if (old_node != begin || !begin_rw_locked)
            node_free_as_reader(old_node);
    }

    return node;
}

// Search for parent of node given by path
Node *find_parent(const char *path, char *subfolder_name, Node *begin, bool own) {
    char *subpath = make_path_to_parent(path, subfolder_name);

    if (!subpath)
        return NULL;

    Node *result = find_node(subpath, begin, own);
    free(subpath);

    return result;
}

// Search for parent of node given by path
Node *get_child(Node *parent, const char *name) {
    return (Node *) hmap_get(parent->sub_folders, name);
}

// Change parent after moving node
void change_parent(Node *node, Node *new_parent) {
    node->parent = new_parent;
}
