#include <stdio.h>

int main(void) {
	int a[50], n, i, j, temp = 0;

	printf("Enter how many numbers you want:\n");
	scanf("%d", &n);
	printf("Enter the %d elements:\n", n);
	for (i = 0; i < n; i++) {
		scanf("%d", &a[i]);
	}

	printf("\nThe given array is:\n");
	for (i = 0; i < n; i++) {
		printf("%d\n", a[i]);
	}

	for (i = 0; i < n; i++) {
		for (j = i + 1; j < n; j++) {
			if (a[i] > a[j]) {
				temp = a[i];
				a[i] = a[j];
				a[j] = temp;
			}
		}
	}

	printf("\nThe sorted array is:\n");
	for (i = 0; i < n; i++) {
		printf("%d\n", a[i]);
	}

	return 0;
}
