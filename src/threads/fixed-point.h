#pragma once
#include <stdint.h>

struct real {
    int value;
};

struct real
convert_int_to_fixed(int n); 

int
convert_fixed_to_int_zero(struct real x);

int
convert_fixed_to_int_nearest(struct real x);

struct real
real_add_real(struct real x, struct real y);

struct real
real_add_int(struct real x, int y); 

struct real
real_sub_real(struct real x, struct real y); 

struct real
real_sub_int(struct real x, int y); 

struct real
real_mul_real(struct real x, struct real y); 

struct real
real_mul_int(struct real x, int y); 

struct real
real_div_real(struct real x, struct real y); 

struct real
real_div_int(struct real x, int y); 
