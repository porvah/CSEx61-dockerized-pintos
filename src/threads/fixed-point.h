#pragma once

int real_f = 1 << 14;

struct real {
    int value
};

struct real
convert_int_to_fixed(int n) {
    int val = n * real_f;
    struct real result = { val };
    return result;
}

int
convert_fixed_to_int_zero(struct real x) {
    return x.value / real_f;
}

int
convert_fixed_to_int_nearest(struct real x) {
    if (x >= 0)
        return (x.value + real_f / 2) / real_f;
    else
        return (x.value - real_f / 2) / real_f;
}

struct real
real_add_real(struct real x, struct real y) {
    struct real res;
    res.value = x.value + y.value;
    return res;
}

struct real
real_add_int(struct real x, int y) {
    struct real res;
    res.value = x.value + (y * real_f);
    return res;
}

struct real
real_sub_real(struct real x, struct real y) {
    struct real res;
    res.value = x.value - y.value;
    return res;
}

struct real
real_sub_int(struct real x, int y) {
    struct real res;
    res.value = x.value - (y * real_f);
    return res;
}

struct real
real_mul_real(struct real x, struct real y) {
    int val = ((int64_t) x.value) * y.value / real_f;
    struct real res = { val };
    return res;
}

struct real
real_mul_int(struct real x, int y) {
    struct real res;
    res.value = x.value * y;
    return res;
}

struct real
real_div_real(struct real x, struct real y) {
    int val = ((int64_t) x.value) * real_f / y.value;
    struct real res = { val };
    return res;
}

struct real
real_div_int(struct real x, int y) {
    struct real res;
    res.value = x.value / y;
    return res;
}

