#include <stdio.h>
#include <math.h>
 
int main(void) {
	float side, surfArea, volume;
 
	printf("Enter the length of an edge: ");
	scanf("%f", &side);

	surfArea = 6.0 * side * side;
	volume = pow (side, 3);

	printf("Surface area = %6.2f and Volume = %6.2f\n", surfArea, volume);
}
