#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <printf.h>

#include "HashMap.h"
#include "Tree.h"
#include "path_utils.h"
#include "tree_utils.h"

#define ENOTALLOW -1 // Trying to move node to it's sub folder

struct Tree {
    Node *root;
};

Tree *tree_new() {
    Tree *tree = (Tree *) safe_malloc(sizeof(Tree));

    tree->root = node_new(NULL);

    return tree;
}

void tree_free(Tree *tree) {
    node_free(tree->root, true);
    free(tree);
}

char *tree_list(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return NULL;

    Node *node = find_node(path, tree->root, false);

    if (!node) {
        return NULL;
    }

    // gets node as reader before reading from map
    node_get_as_reader(node);
    char * result;

    if (hmap_size(get_sub_folders(node)) > 0) {
        result = make_map_contents_string(get_sub_folders(node));
    } else {
        result = calloc(1, sizeof(char));
        result[0] = '\0';
    }

    decrease_counter(node, tree->root);
    node_free_as_reader(node);

    return result;
}

// Clean changes in tree after create/remove, also if error is returned
void tree_create_remove_cleanup(Tree *tree, Node *to_free) {
    decrease_counter(to_free, tree->root);
    node_free_as_writer(to_free);
}

int tree_create(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EEXIST;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(path, name, tree->root, false);

    if (parent == NULL) {
        return ENOENT;
    }

    // gets parent node as writer before adding new node
    node_get_as_writer(parent);

    // we need to check this as writer because we don't want any process to change
    // anything after this and before adding new node to map
    if (hmap_get(get_sub_folders(parent), name) != NULL) {
        tree_create_remove_cleanup(tree, parent);
        return EEXIST;
    }

    hmap_insert(get_sub_folders(parent), name, (void *) node_new(parent));
    tree_create_remove_cleanup(tree, parent);

    return 0;
}

int tree_remove(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return EINVAL;

    if (strcmp(path, "/") == 0)
        return EBUSY;

    char name[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent = find_parent(path, name, tree->root, false);
    Node *child;

    if (parent == NULL ) {
        return ENOENT;
    }

    // gets parent node as writer before removing
    node_get_as_writer(parent);

    // we need to check this as writer because we don't want any process to change
    // anything after this and before removing child
    if ((child = get_child(parent, name)) == NULL) {
        tree_create_remove_cleanup(tree, parent);
        return ENOENT;
    }

    if (node_free(child, false) == ENOTEMPTY) {
        tree_create_remove_cleanup(tree, parent);
        return ENOTEMPTY;
    }

    hmap_remove(get_sub_folders(parent), name);
    tree_create_remove_cleanup(tree, parent);

    return 0;
}

// Decrease counters in tree after move, also if error is returned.
void decrease_counters_for_move(Tree *tree, Node *LCA, Node *source, Node *target) {
    decrease_counter(LCA, tree->root);
    decrease_counter(source, LCA);
    decrease_counter(target, LCA);
}

// Clean changes in tree after move, also if error is returned.
void tree_move_cleanup(Tree *tree, Node *LCA, Node *source, Node *target) {
    decrease_counters_for_move(tree, LCA, source, target);

    if (source != target)
        node_free_as_writer(target);

    node_free_as_writer(source);
}

// Checks basic things before move.
int check_basics_move(const char *source, const char *target) {
    if (!is_path_valid(source) || !is_path_valid(target))
        return EINVAL;
    if (strcmp(source, "/") == 0)
        return EBUSY;
    if (strcmp(target, "/") == 0)
        return EEXIST;
    if (strlen(source) < strlen(target) && strncmp(source, target, strlen(source)) == 0)
        return ENOTALLOW;

    return 0;
}

// Remove lock from LCA end locks parent_source and parent_target.
int lock_parents(Tree *tree, Node *LCA, Node *parent_source, Node *parent_target) {
    if (parent_source == NULL || parent_target == NULL) {
        decrease_counters_for_move(tree, LCA, parent_source, parent_target);
        node_free_as_writer(LCA);
        return ENOENT;
    }

    if (parent_source != LCA)
        node_get_as_writer(parent_source);

    if (parent_source != parent_target && parent_target != LCA)
        node_get_as_writer(parent_target);

    if (parent_source != LCA && parent_target != LCA)
        node_free_as_writer(LCA);

    return 0;
}

int tree_move(Tree *tree, const char *source, const char *target) {
    int check;
    if((check = check_basics_move(source, target)) != 0)
        return check;

    char *new_source = NULL, *new_target = NULL;
    char *LCA_string = find_LCA(source, target, &new_source, &new_target);
    Node * LCA = find_node(LCA_string, tree->root, false);
    free(LCA_string);

    if (LCA == NULL) {
        free(new_source);
        free(new_target);
        return ENOENT;
    }

    // While searching for parents of source and target we're locking LCA as writer of source and target,
    // so no other process can go into LCA's tree and cause deadlock
    node_get_as_writer(LCA);

    char name_source[MAX_FOLDER_NAME_LENGTH + 1], name_target[MAX_FOLDER_NAME_LENGTH + 1];
    Node * parent_source = find_parent(new_source, name_source, LCA, true);
    Node * parent_target = find_parent(new_target, name_target, LCA, true);
    free(new_source);
    free(new_target);

    if ((check = lock_parents(tree, LCA, parent_source, parent_target)) != 0)
        return check;

    Node *to_move;
    if ((to_move = get_child(parent_source, name_source)) == NULL) {
        tree_move_cleanup(tree, LCA, parent_source, parent_target);
        return ENOENT;
    }

    if (strcmp(source, target) == 0) {
        tree_move_cleanup(tree, LCA, parent_source, parent_target);
        return 0;
    }

    if (hmap_get(get_sub_folders(parent_target), name_target) != NULL) {
        tree_move_cleanup(tree, LCA, parent_source, parent_target);
        return EEXIST;
    }

    node_get_as_remover(to_move);

    hmap_remove(get_sub_folders(parent_source), name_source);
    hmap_insert(get_sub_folders(parent_target), name_target, (void *) to_move);
    change_parent(to_move, parent_target);

    tree_move_cleanup(tree, LCA, parent_source, parent_target);

    return 0;
}


