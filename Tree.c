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
    int readers_count, writer_count, reader_wait, writers_wait;
    int change; // 0 - no one, 1 - readers, 2 - writer
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

    if (pthread_mutex_init(node->lock, 0) != 0)
        syserr("mutex init failed");
    if (pthread_cond_init(node->readers, 0) != 0)
        syserr("cond init failed");
    if (pthread_cond_init(node->writers, 0) != 0)
        syserr("cond init failed");

    node->readers_count = 0;
    node->writer_count = 0;
    node->reader_wait = 0;
    node->writers_wait = 0;
    node->readers_to_wake = 0;
    node->change = 0;

    return node;
}

Tree *tree_new() {
    Tree *tree = (Tree *) safe_malloc(sizeof(Tree));

    tree->root = node_new();

    return tree;
}

//void signal_with_change(Node *node, pthread_cond_t *who, int new_change) {
//    node->change = new_change;
//
//    if (pthread_cond_signal(who) != 0)
//        syserr ("cond signal failed");
//}

//void node_get_as_reader(Node * node) {
//    if (pthread_mutex_lock(node->lock) != 0)
//        syserr("lock failed");
//
//    while (node->writer_count + node->writers_wait + node->change > 0) {
//        node->reader_wait++;
//        if (pthread_cond_wait(node->readers, node->lock) != 0)
//            syserr("cond wait failed");
//
//        node->reader_wait--;
//        if (node->change == 1) {
//            node->readers_to_wake--;
//            break;
//        }
//    }
//
//    node->readers_count++;
//
//    if(node->readers_to_wake > 0)
//        signal_with_change(node, node->readers, 1);
//    else
//        node->change = 0;
//
//    if (pthread_mutex_unlock(node->lock) != 0)
//        syserr ("unlock failed");
//}
//
//void node_get_as_writer(Node * node) {
//    if (pthread_mutex_lock(node->lock) != 0)
//        syserr("lock failed");
//
//    while (node->readers_count + node->writer_count + node->change > 0) {
//        node->writers_wait++;
//
//        if (pthread_cond_wait(node->writers, node->lock) != 0)
//            syserr("cond wait failed");
//
//        node->writers_wait--;
//
//        if (node->change == 2)
//            node->change = 0;
//    }
//
//    node->writer_count++;
//
//    if (pthread_mutex_unlock(node->lock) != 0)
//        syserr ("unlock failed");
//}
//
//void node_free_as_reader(Node *node) {
//    if (pthread_mutex_lock(node->lock) != 0)
//        syserr("lock failed");
//
//    node->readers_count--;
//
//    if(node->readers_count == 0) {
//        if(node->writers_wait > 0)
//            signal_with_change(node, node->writers, 2);
//        else if(node->reader_wait > 0) {
//            node->readers_to_wake = node->reader_wait;
//            signal_with_change(node, node->readers, 1);
//        }
//    }
//
//    if (pthread_mutex_unlock(node->lock) != 0)
//        syserr ("unlock failed");
//
//}
//
//void node_free_as_writer(Node *node) {
//    if (pthread_mutex_lock(node->lock) != 0)
//        syserr("lock failed");
//
//    node->writer_count--;
//
//    if(node->reader_wait > 0) {
//        node->readers_to_wake = node->reader_wait;
//        signal_with_change(node,node->readers, 1);
//    } else if(node->writers_wait > 0) {
//        signal_with_change(node, node->writers, 2);
//    }
//
//    if (pthread_mutex_unlock(node->lock) != 0)
//        syserr ("unlock failed");
//
//}

static int node_free(Node *node, bool delete_all) {
    if (!delete_all && hmap_size(node->sub_folders) != 0) {
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

static Node *find_node(Tree *tree, const char *path) {
    Node *node = tree->root;
    void *sth;

    char component[MAX_FOLDER_NAME_LENGTH + 1];
    const char *subpath = path;
    while ((subpath = split_path(subpath, component))) {
        sth = hmap_get(node->sub_folders, component);

        if (!sth) {
            return NULL;
        }

        node = (Node *) sth;
    }

    return node;
}

static Node *find_parent(Tree *tree, const char *path, char *subfolder_name) {
    char *subpath = make_path_to_parent(path, subfolder_name);

    if (!subpath)
        return NULL;

    Node * result = find_node(tree, subpath);

    free(subpath);

    return result;
}

char *tree_list(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return NULL;

    Node *node = find_node(tree, path);

    if (!node) {
        return NULL;
    }

    char * result;

    if (hmap_size(node->sub_folders) > 0) {
        result = make_map_contents_string(node->sub_folders);
    } else {
        result = calloc(1, sizeof(char));
        result[0] = '\0';
    }

    return result;
}

int tree_create(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EEXIST;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(tree, path, name);

    if (parent == NULL) {
        return ENOENT;
    }

    if (hmap_get(parent->sub_folders, name) != NULL) {
        return EEXIST;
    }

    hmap_insert(parent->sub_folders, name, (void *) node_new());

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

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(tree, path, name);
    Node *child;

    if (parent == NULL ) {
        return ENOENT;
    }

    if ((child = get_child(parent, name)) == NULL) {
        return ENOENT;
    }

    if (node_free(child, false) == ENOTEMPTY) {
        return ENOTEMPTY;
    }

    hmap_remove(parent->sub_folders, name);

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

    if ((to_move = get_child(parent_source, name_source)) == NULL) {
        return ENOENT;
    }

    if (strcmp(source, target) == 0) {
        return 0;
    }
    if (strncmp(source, target, strlen(source)) == 0) {
        return ENOTALLOW;
    }
    if (parent_target == NULL) {
        return ENOENT;
    }

   if (hmap_get(parent_target->sub_folders, name_target) != NULL) {
        return EEXIST;
    }

    hmap_remove(parent_source->sub_folders, name_source);
    hmap_insert(parent_target->sub_folders, name_target, (void *) to_move);

    return 0;
}


