#include <stdlib.h>
#include <stdio.h>

typedef struct _node {
	int data;
	struct _node *link;
} node;

node *front, *rear;

void insert(int info) {
	node *temp;
	temp = malloc(sizeof(node));
	if (temp == NULL)
		printf(" Out of Memory !! Overflow !!!");
	else {
		temp->data = info;
		temp->link = NULL;

		if (front == NULL) {
			front = rear = temp;
		} else {
			rear->link = temp;
			rear = temp;
		}
	}
}
 
int delete(void) {
	int info;
	node *t;

	if (front == NULL) {
		printf("Queue is empty\n");
		info = -1;
	} else {
		t = front;
		info = front->data;
		if (front == rear)
			rear = NULL;
		front = front->link;
		t->link = NULL;
		free(t);
	}
	return info;
}
 
void display() {
	node *t;

	if (front == NULL)
		printf("Queue is empty\n");
	else {
		t = front;
		while (t) {
			printf("[%d]->", t->data);
			t = t->link;
		}
	}
}

int main(void) {
	int opn, elem;

	do {
		printf("Linked List Implementation of QUEUE Operations ### \n\n");
		printf("Press 1-Insert, 2-Delete, 3-Display,4-Exit\n");
		printf("Your option ? ");
		scanf("%d", &opn);

		switch (opn) {
			case 1:
				printf("Insert value of node: ");
				scanf("%d", &elem);
				insert(elem);
				break;

			case 2:
				elem = delete();
				if (elem != -1)
					printf("Deleted node: %d\n", elem);
				break;

			case 3:
				printf("Linked List Implementation of Queue: Status:\n");
				display();
				break;

			case 4:
				printf("Terminating.\n");
				break;

			default:
				printf("Invalid option\n");
		}
	} while (opn != 4);
}
