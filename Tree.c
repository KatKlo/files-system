#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <printf.h>

#include "HashMap.h"
#include "Tree.h"
#include "path_utils.h"
#include "err.h"

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

struct Tree {
    Node *root;
};

static void *safe_malloc(size_t size) {
    void *res = malloc(size);

    if (res == NULL)
        syserr("malloc failed");

    return res;
}

static Node *node_new() {
    Node *node = (Node *) safe_malloc(sizeof(Node));

    node->sub_folders = hmap_new();

    if (!node->sub_folders)
        syserr("creating new hmap failed");

    node->lock = (pthread_mutex_t *) safe_malloc(sizeof(pthread_mutex_t));
    node->readers = (pthread_cond_t *) safe_malloc(sizeof(pthread_cond_t));
    node->writers = (pthread_cond_t *) safe_malloc(sizeof(pthread_cond_t));
    node->remove = (pthread_cond_t *) safe_malloc(sizeof(pthread_cond_t));

    if (pthread_mutex_init(node->lock, 0) != 0)
        syserr("mutex init failed");
    if (pthread_cond_init(node->readers, 0) != 0)
        syserr("cond init failed");
    if (pthread_cond_init(node->writers, 0) != 0)
        syserr("cond init failed");
    if (pthread_cond_init(node->remove, 0) != 0)
        syserr("cond init failed");
    node->rcount = 0;
    node->wcount = 0;
    node->rwait = 0;
    node->wwait = 0;
    node->removewait = 0;
    node->readers_to_wake = 0;
    node->dupa = 0;
    node->change = 0;

    return node;
}

Tree *tree_new() {
    Tree *tree = (Tree *) safe_malloc(sizeof(Tree));

    tree->root = node_new();

    return tree;
}

void signal_with_change(Node *node, pthread_cond_t *who, int new_change) {
    node->change = new_change;

    if (pthread_cond_signal(who) != 0)
        syserr ("cond signal failed");
}

static void decrease_dupa(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->dupa--;

    if (node->dupa + node->rwait + node->wwait + node->rcount + node->wcount + node->change == 0)
        if (node->removewait > 0)
            signal_with_change(node, node->remove, 3);

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

static void increase_dupa(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->dupa++;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

static void decrease_dupa_path(Node ** nodes_path, size_t nodes_path_len) {
    for (int i = 0; i < nodes_path_len; i++) {
        decrease_dupa(nodes_path[i]);
    }

    free(nodes_path);
}

void node_get_as_reader(Node * node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    while (node->wcount + node->wwait + node->change > 0) {
        node->rwait++;
        if (pthread_cond_wait(node->readers, node->lock) != 0)
            syserr("cond wait failed");

        node->rwait--;
        if (node->change == 1) {
            node->readers_to_wake--;
            break;
        }
    }

    node->rcount++;

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

    while (node->rcount + node->wcount + node->change > 0) {
        node->wwait++;

        if (pthread_cond_wait(node->writers, node->lock) != 0)
            syserr("cond wait failed");

        node->wwait--;

        if (node->change == 2)
            node->change = 0;
    }

    node->wcount++;

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

void node_get_as_remove(Node * node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    while (node->rcount + node->wcount + node->rwait + node->wwait + node->change + node->dupa > 0) {
        node->removewait++;

        if (pthread_cond_wait(node->remove, node->lock) != 0)
            syserr("cond wait failed");

        node->removewait--;

        if (node->change == 3)
            node->change = 0;
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");
}

void node_free_as_reader(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->rcount--;

    if(node->rcount == 0 && node->readers_to_wake == 0) {
        if(node->wwait > 0)
            signal_with_change(node, node->writers, 2);
        else if(node->rwait > 0) {
            node->readers_to_wake = node->rwait;
            signal_with_change(node, node->readers, 1);
        } else if (node->removewait > 0 && node->dupa == 0) {
            signal_with_change(node, node->remove, 3);
        }
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");

}

void node_free_as_writer(Node *node) {
    if (pthread_mutex_lock(node->lock) != 0)
        syserr("lock failed");

    node->wcount--;

    if(node->rwait > 0) {
        node->readers_to_wake = node->rwait;
        signal_with_change(node,node->readers, 1);
    } else if(node->wwait > 0) {
        signal_with_change(node, node->writers, 2);
    } else if (node->removewait > 0 && node->dupa == 0) {
        signal_with_change(node, node->remove, 3);
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");

}

static int node_free(Node *node, bool delete_all) {
    node_get_as_remove(node);

    if (!delete_all && hmap_size(node->sub_folders) > 0) {
        return ENOTEMPTY;
    }

    const char *key;
    void *value;

    HashMapIterator it = hmap_iterator(node->sub_folders);
    while (hmap_next(node->sub_folders, &it, &key, &value))
        node_free((Node *) value, true);

    hmap_free(node->sub_folders);

    if (pthread_cond_destroy(node->readers) != 0)
        syserr("cond destroy failed");
    free(node->readers);
    if (pthread_cond_destroy(node->writers) != 0)
        syserr("cond destroy failed");
    free(node->writers);
    if (pthread_cond_destroy(node->remove) != 0)
        syserr("mutex destroy failed");
    free(node->remove);
    if (pthread_mutex_destroy(node->lock) != 0)
        syserr("mutex destroy failed");
    free(node->lock);

    free(node);

    return 0;
}

void tree_free(Tree *tree) {
    node_free(tree->root, true);
    free(tree);
}

static Node *find_node(const char *path, Node ***nodes_path, size_t *nodes_path_len, Node *begin, bool own) {
    Node *node = begin;
    void *sth;

    int count = 0;

    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char *subpath = path;
    while ((subpath = split_path(subpath, component))) {
        if (node != begin || !own)
            node_get_as_reader(node);

        sth = hmap_get(node->sub_folders, component);

        if (!sth) {
            if (node != begin || !own)
                node_free_as_reader(node);
            return NULL;
        }

        Node *old_node = node;

        node = (Node *) sth;
        increase_dupa(node);

        if (count == *nodes_path_len) {
            count = count * 2 + 1;
            *nodes_path = (Node **) realloc(*nodes_path, count * sizeof(Node *));
        }
        (*nodes_path)[(*nodes_path_len)++] = node;

        if (old_node != begin || !own)
            node_free_as_reader(old_node);
    }

    return node;
}

static Node *
find_parent(const char *path, char *subfolder_name, Node ***nodes_path, size_t *nodes_path_len, Node *begin, bool own) {
    char *subpath = make_path_to_parent(path, subfolder_name);

    if (!subpath)
        return NULL;

    Node * result = find_node(subpath, nodes_path, nodes_path_len, begin, own);

    free(subpath);

    return result;
}

char *tree_list(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return NULL;

    Node ** nodes_path = NULL;
    size_t nodes_path_len = 0;

    Node *node = find_node(path, &nodes_path, &nodes_path_len, tree->root, false);

    if (!node) {
        decrease_dupa_path(nodes_path, nodes_path_len);
        return NULL;
    }

    node_get_as_reader(node);

    char * result;

    if (hmap_size(node->sub_folders) > 0) {
        result = make_map_contents_string(node->sub_folders);
    } else {
        result = calloc(1, sizeof(char));
        result[0] = '\0';
    }

    decrease_dupa_path(nodes_path, nodes_path_len);

    node_free_as_reader(node);

    return result;
}

int tree_create(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EEXIST;

    Node ** nodes_path = NULL;
    size_t nodes_path_len = 0;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(path, name, &nodes_path, &nodes_path_len, tree->root, false);

    if (parent == NULL) {
        decrease_dupa_path(nodes_path, nodes_path_len);
        return ENOENT;
    }

    node_get_as_writer(parent);

    if (hmap_get(parent->sub_folders, name) != NULL) {
        decrease_dupa_path(nodes_path, nodes_path_len);
        node_free_as_writer(parent);
        return EEXIST;
    }

    hmap_insert(parent->sub_folders, name, (void *) node_new());

    decrease_dupa_path(nodes_path, nodes_path_len);

    node_free_as_writer(parent);

    return 0;
}

Node * get_child(Node *parent, const char *name) {
    Node * sth = hmap_get(parent->sub_folders, name);

    if (sth == NULL)
        return NULL;

    return (Node *) sth;
}

int tree_remove(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EBUSY;

    Node ** nodes_path = NULL;
    size_t nodes_path_len = 0;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(path, name, &nodes_path, &nodes_path_len, tree->root, false);
    Node *child;

    if (parent == NULL ) {
        decrease_dupa_path(nodes_path, nodes_path_len);
        return ENOENT;
    }

    node_get_as_writer(parent);

    if ((child = get_child(parent, name)) == NULL) {
        decrease_dupa_path(nodes_path, nodes_path_len);
        node_free_as_writer(parent);
        return ENOENT;
    }

    if (node_free(child, false) == ENOTEMPTY) {
        decrease_dupa_path(nodes_path, nodes_path_len);
        node_free_as_writer(parent);
        return ENOTEMPTY;
    }

    hmap_remove(parent->sub_folders, name);

    decrease_dupa_path(nodes_path, nodes_path_len);
    node_free_as_writer(parent);

    return 0;
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

    return found_parent;

}

int tree_move(Tree *tree, const char *source, const char *target) {
    if (!is_path_valid(source) || !is_path_valid(target))
        return EINVAL;
    if (strcmp(source, "/") == 0)
        return EBUSY;
    if (strcmp(target, "/") == 0)
        return EEXIST;

    if (strlen(source) < strlen(target) && strncmp(source, target, strlen(source)) == 0) {
        return ENOTALLOW;
    }

    Node ** nodes_path_source = NULL;
    size_t nodes_path_len_source = 0;
    Node ** nodes_path_target = NULL;
    size_t nodes_path_len_target = 0;
    Node ** nodes_path_parent = NULL;
    size_t nodes_path_len_parent = 0;
    char *new_source = NULL, *new_target = NULL;
    char *parent_string = find_both_parent(source, target, &new_source, &new_target);

    Node *parent = find_node(parent_string, &nodes_path_parent, &nodes_path_len_parent, tree->root, false);

    if (parent == NULL) {
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        return ENOENT;
    }

    node_get_as_writer(parent);

    char name_source[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_source = find_parent(new_source, name_source, &nodes_path_source, &nodes_path_len_source, parent,
                                      true);
    Node *to_move;

    if (parent_source == NULL) {
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        decrease_dupa_path(nodes_path_source, nodes_path_len_source);
        node_free_as_writer(parent);
        return ENOENT;
    }

    char name_target[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_target = find_parent(new_target, name_target, &nodes_path_target, &nodes_path_len_target, parent,
                                      true);

    if (parent_source != parent)
        node_get_as_writer(parent_source);

    if ((to_move = get_child(parent_source, name_source)) == NULL) {
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        decrease_dupa_path(nodes_path_source, nodes_path_len_source);
        decrease_dupa_path(nodes_path_target, nodes_path_len_target);

        if (parent_source != parent)
            node_free_as_writer(parent_source);
        node_free_as_writer(parent);
        return ENOENT;
    }

    if (strcmp(source, target) == 0) {
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        decrease_dupa_path(nodes_path_source, nodes_path_len_source);
        decrease_dupa_path(nodes_path_target, nodes_path_len_target);

        if (parent_source != parent)
            node_free_as_writer(parent_source);
        node_free_as_writer(parent);
        return 0;
    }

    if (parent_target == NULL) {
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        decrease_dupa_path(nodes_path_source, nodes_path_len_source);
        decrease_dupa_path(nodes_path_target, nodes_path_len_target);
        if (parent_source != parent)
            node_free_as_writer(parent_source);
        node_free_as_writer(parent);
        return ENOENT;
    }

    if (parent_source != parent_target && parent_target != parent)
        node_get_as_writer(parent_target);

    if (parent_source != parent && parent_target != parent)
        node_free_as_writer(parent);

    if (hmap_get(parent_target->sub_folders, name_target) != NULL) {
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        decrease_dupa_path(nodes_path_source, nodes_path_len_source);
        decrease_dupa_path(nodes_path_target, nodes_path_len_target);

        if (parent_source != parent_target)
            node_free_as_writer(parent_target);

        node_free_as_writer(parent_source);

        return EEXIST;
    }

    node_get_as_remove(to_move);

    hmap_remove(parent_source->sub_folders, name_source);
    hmap_insert(parent_target->sub_folders, name_target, (void *) to_move);

    decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
    decrease_dupa_path(nodes_path_source, nodes_path_len_source);
    decrease_dupa_path(nodes_path_target, nodes_path_len_target);

    if (parent_source != parent_target)
        node_free_as_writer(parent_target);

    node_free_as_writer(parent_source);


    return 0;
}


