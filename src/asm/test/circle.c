#include <stdio.h>
#include <math.h>
 
int main(void) {
	float radius, area;
 
	printf("Enter the radius of a circle\n");
	scanf ("%f", &radius);
 
	area = M_PI * pow (radius,2);
 
	printf ("Area of a circle = %5.2f\n", area);
}
