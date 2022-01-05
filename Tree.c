#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <printf.h>

#include "HashMap.h"
#include "Tree.h"
#include "path_utils.h"
#include "tree_utils.h"

struct Tree {
    Node *root;
};

Tree *tree_new() {
    Tree *tree = (Tree *) safe_malloc(sizeof(Tree));

    tree->root = node_new();

    return tree;
}

void tree_free(Tree *tree) {
    node_free(tree->root, true);
    free(tree);
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
    free(parent_string);

    if (parent == NULL) {
        free(new_source);
        free(new_target);
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        return ENOENT;
    }

    node_get_as_writer(parent);

    char name_source[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_source = find_parent(new_source, name_source, &nodes_path_source, &nodes_path_len_source, parent,
                                      true);
    Node *to_move;
    free(new_source);

    if (parent_source == NULL) {
        free(new_target);
        decrease_dupa_path(nodes_path_parent, nodes_path_len_parent);
        decrease_dupa_path(nodes_path_source, nodes_path_len_source);
        node_free_as_writer(parent);
        return ENOENT;
    }

    char name_target[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_target = find_parent(new_target, name_target, &nodes_path_target, &nodes_path_len_target, parent,
                                      true);
    free(new_target);

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


