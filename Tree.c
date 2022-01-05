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

    tree->root = node_new(NULL);

    return tree;
}

void tree_free(Tree *tree) {
    node_free(tree->root, true);
    free(tree);
}

void tree_list_cleanup(Tree *tree, Vector *path_to_decrease, Node *to_free) {
    decrease_counter_path(path_to_decrease, tree->root);

    if (to_free != NULL)
        node_free_as_reader(to_free);
}

char *tree_list(Tree *tree, const char *path) {
    if (!is_path_valid(path))
        return NULL;

    Node *node = find_node(path, tree->root, false);

    if (!node) {
        return NULL;
    }

    node_get_as_reader(node);
    char * result;

    if (hmap_size(get_subfolders(node)) > 0) {
        result = make_map_contents_string(get_subfolders(node));
    } else {
        result = calloc(1, sizeof(char));
        result[0] = '\0';
    }

    tree_list_cleanup(tree, get_nodes_path(node), node);

    return result;
}

void tree_create_cleanup(Tree *tree, Vector *path_to_decrease, Node *to_free) {
    decrease_counter_path(path_to_decrease, tree->root);

    if (to_free != NULL)
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

    node_get_as_writer(parent);

    if (hmap_get(get_subfolders(parent), name) != NULL) {
        tree_create_cleanup(tree, get_nodes_path(parent), parent);
        return EEXIST;
    }

    hmap_insert(get_subfolders(parent), name, (void *) node_new(get_nodes_path(parent)));
    tree_create_cleanup(tree, get_nodes_path(parent), parent);

    return 0;
}

void tree_remove_cleanup(Tree *tree, Vector *path_to_decrease, Node *to_free) {
    decrease_counter_path(path_to_decrease, tree->root);

    if (to_free != NULL)
        node_free_as_writer(to_free);
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

    node_get_as_writer(parent);

    if ((child = get_child(parent, name)) == NULL) {
        tree_remove_cleanup(tree, get_nodes_path(parent), parent);
        return ENOENT;
    }

    if (node_free(child, false) == ENOTEMPTY) {
        tree_remove_cleanup(tree, get_nodes_path(parent), parent);
        return ENOTEMPTY;
    }

    hmap_remove(get_subfolders(parent), name);
    tree_remove_cleanup(tree, get_nodes_path(parent), parent);

    return 0;
}

void tree_move_cleanup(Tree *tree, Node *parent, Node *parent_source, Node *parent_target, bool free_parent) {
    if (parent != NULL)
        decrease_counter_path(get_nodes_path(parent), tree->root);

    if (parent_source != NULL)
        decrease_counter_path(get_nodes_path(parent_source), parent);

    if (parent_target != NULL)
        decrease_counter_path(get_nodes_path(parent_target), parent);

    if (parent != NULL && free_parent && parent != parent_source)
        node_free_as_writer(parent);

    if (parent_target != NULL && parent_source != parent_target)
        node_free_as_writer(parent_target);

    if (parent_source != NULL)
        node_free_as_writer(parent_source);
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

    char *new_source = NULL, *new_target = NULL;
    char *parent_string = find_both_parent(source, target, &new_source, &new_target);

    Node *parent = find_node(parent_string, tree->root, false);
    free(parent_string);

    if (parent == NULL) {
        free(new_source);
        free(new_target);
        return ENOENT;
    }

    node_get_as_writer(parent);

    char name_source[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_source = find_parent(new_source, name_source, parent, true);
    Node *to_move;
    free(new_source);

    if (parent_source == NULL) {
        free(new_target);
        tree_move_cleanup(tree, parent, NULL, NULL, true);
        return ENOENT;
    }

    if (parent_source != parent)
        node_get_as_writer(parent_source);

    if ((to_move = get_child(parent_source, name_source)) == NULL) {
        free(new_target);
        tree_move_cleanup(tree, parent, parent_source, NULL, true);
        return ENOENT;
    }

    if (strcmp(source, target) == 0) {
        free(new_target);
        tree_move_cleanup(tree, parent, parent_source, NULL, true);
        return 0;
    }

    char name_target[MAX_FOLDER_NAME_LENGTH + 1];
    Node *parent_target = find_parent(new_target, name_target, parent, true);
    free(new_target);

    if (parent_target == NULL) {
        tree_move_cleanup(tree, parent, parent_source, NULL, true);
        return ENOENT;
    }

    if (parent_source != parent_target && parent_target != parent)
        node_get_as_writer(parent_target);

    if (parent_source != parent && parent_target != parent)
        node_free_as_writer(parent);

    if (hmap_get(get_subfolders(parent_target), name_target) != NULL) {
        tree_move_cleanup(tree, parent, parent_source, parent_target, false);
        return EEXIST;
    }

    node_get_as_remover(to_move);

    hmap_remove(get_subfolders(parent_source), name_source);
    hmap_insert(get_subfolders(parent_target), name_target, (void *) to_move);
    change_nodes_paths(to_move, parent_target);

    tree_move_cleanup(tree, parent, parent_source, parent_target, false);

    return 0;
}


