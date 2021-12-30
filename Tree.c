#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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

    while (node->rcount + node->wcount + node->rwait + node->wwait + node->change > 0) {
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

    if(node->rcount == 0) {
        if(node->wwait > 0)
            signal_with_change(node, node->writers, 2);
        else if(node->rwait > 0) {
            node->readers_to_wake = node->rwait;
            signal_with_change(node, node->readers, 1);
        } else if (node->removewait > 0) {
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
    } else if (node->removewait > 0) {
        signal_with_change(node, node->remove, 3);
    }

    if (pthread_mutex_unlock(node->lock) != 0)
        syserr ("unlock failed");

}

static int node_free(Node *node, bool delete_all) {
    node_get_as_remove(node);

    if (!delete_all && hmap_size(node->sub_folders) != 0) {
        node_free_as_writer(node);
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
    if (pthread_cond_destroy(node->writers) != 0)
        syserr("cond destroy failed");
    if (pthread_cond_destroy(node->remove) != 0)
        syserr("mutex destroy failed");
    if (pthread_mutex_destroy(node->lock) != 0)
        syserr("mutex destroy failed");

    free(node);

    return 0;
}

void tree_free(Tree *tree) {
    node_free(tree->root, true);
}

static Node *find_node(Tree *tree, const char *path) {
    Node *node = tree->root;
    void *sth;

    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char *subpath = path;
    while ((subpath = split_path(subpath, component))) {
        node_get_as_reader(node);
        sth = hmap_get(node->sub_folders, component);
        node_free_as_reader(node);

        if (!sth)
            return NULL;

        node = (Node *) sth;
    }

    return node;
}

static Node *find_parent(Tree *tree, const char *path, char *subfolder_name) {
    const char *subpath = make_path_to_parent(path, subfolder_name);

    if (!subpath)
        return NULL;

    return find_node(tree, subpath);
}

char *tree_list(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return NULL;

    Node *node = find_node(tree, path);

    if (!node)
        return NULL;

    node_get_as_reader(node);

    char * result = make_map_contents_string(node->sub_folders);

    node_free_as_reader(node);

    return result;
}

int tree_create(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EEXIST;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(tree, path, name);

    if (parent == NULL)
        return ENOENT;

    node_get_as_writer(parent);

    bool sth = hmap_insert(parent->sub_folders, name, (void *) node_new());

    node_free_as_writer(parent);

    if (!sth)
        return EEXIST;

    return 0;
}

int tree_remove(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EBUSY;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(tree, path, name);
    Node *child;

    if (parent == NULL )
        return ENOENT;

    node_get_as_writer(parent);

    if ((child = (Node *) hmap_get(parent->sub_folders, name)) == NULL) {
        node_free_as_writer(parent);
        return ENOENT;
    }

    if (node_free(child, false) == ENOTEMPTY) {
        node_free_as_writer(parent);
        return ENOTEMPTY;
    }

    hmap_remove(parent->sub_folders, name);

    node_free_as_writer(parent);

    return 0;
}

int tree_move(Tree *tree, const char *source, const char *target) {
    if (!is_path_valid(source) || !is_path_valid(target))
        return EINVAL;
    if (strcmp(source, "/") == 0)
        return EBUSY;
    if (strcmp(target, "/") == 0)
        return EEXIST;

    char name_source[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_source = find_parent(tree, source, name_source);
    Node *to_move;

    char name_target[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_target = find_parent(tree, target, name_target);

    if (strncmp(source, target, strlen(source)) == 0 && strlen(source) != strlen(target)) {
        return ENOTALLOW;
    }

    if (parent_source == NULL) {
        return ENOENT;
    }

    node_get_as_writer(parent_source);

    if ((to_move = (Node *) hmap_get(parent_source->sub_folders, name_source)) == NULL) {
        node_free_as_writer(parent_source);
        return ENOENT;
    }
    if (strcmp(source, target) == 0) {
        node_free_as_writer(parent_source);
        return 0;
    }
    if (strncmp(source, target, strlen(source)) == 0) {
        node_free_as_writer(parent_source);
        return ENOTALLOW;
    }

    if (parent_target == NULL) {
        node_free_as_writer(parent_source);
        return ENOENT;
    }

    if (parent_source != parent_target)
        node_get_as_writer(parent_target);

    if (hmap_get(parent_target->sub_folders, name_target) != NULL) {
        if (parent_source != parent_target)
            node_free_as_writer(parent_target);

        node_free_as_writer(parent_source);
        return EEXIST;
    }

    hmap_remove(parent_source->sub_folders, name_source);
    hmap_insert(parent_target->sub_folders, name_target, (void *) to_move);

    if (parent_source != parent_target)
        node_free_as_writer(parent_target);

    node_free_as_writer(parent_source);

    return 0;
}


