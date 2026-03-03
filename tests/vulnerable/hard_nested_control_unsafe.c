/* HARD: Nested control flow - vulnerability hidden in deep branches.
 * Expected: use-after-free, null-checks
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct Node {
    int value;
    struct Node *next;
} Node;

Node *create_list(int n) {
    Node *head = NULL;
    for (int i = 0; i < n; i++) {
        Node *node = malloc(sizeof(Node));
        if (!node) {
            return head;
        }
        node->value = i;
        node->next = head;
        head = node;
    }
    return head;
}

void process_list(Node *head, int free_early) {
    Node *p = head;
    while (p != NULL) {
        printf("%d ", p->value);
        if (free_early && p->value == 1) {
            free(p);
        }
        p = p->next;   /* use-after-free when free_early and p was freed */
    }
}

void cleanup_list(Node *head) {
    while (head != NULL) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}

int main(void) {
    Node *list = create_list(5);
    if (list) {
        process_list(list, 1);
        cleanup_list(list);
    }
    return 0;
}
