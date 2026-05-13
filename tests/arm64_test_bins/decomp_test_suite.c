// ARM64 Decompiler Test Suite
// Cross-compile: aarch64-linux-gnu-gcc -O0 -static -o decomp_test_suite decomp_test_suite.c
// Run under QEMU: qemu-aarch64 ./decomp_test_suite

#include <stdint.h>
#include <string.h>

// ============================================================
// Test 1: Simple Arithmetic
// ============================================================
int32_t test_add(int32_t a, int32_t b) { return a + b; }
int32_t test_sub(int32_t a, int32_t b) { return a - b; }
int32_t test_mul(int32_t a, int32_t b) { return a * b; }
int32_t test_div_s(int32_t a, int32_t b) { return a / b; }
uint32_t test_div_u(uint32_t a, uint32_t b) { return a / b; }
int32_t test_mod_s(int32_t a, int32_t b) { return a % b; }
int64_t test_mull(int32_t a, int32_t b) { return (int64_t)a * (int64_t)b; }
int64_t test_umull(uint32_t a, uint32_t b) { return (uint64_t)a * (uint64_t)b; }
int32_t test_neg(int32_t a) { return -a; }
int32_t test_and(int32_t a, int32_t b) { return a & b; }
int32_t test_or(int32_t a, int32_t b) { return a | b; }
int32_t test_xor(int32_t a, int32_t b) { return a ^ b; }
int32_t test_not(int32_t a) { return ~a; }
int32_t test_lsl(int32_t a, int32_t b) { return a << b; }
int32_t test_lsr(int32_t a, int32_t b) { return (uint32_t)a >> b; }
int32_t test_asr(int32_t a, int32_t b) { return a >> b; }

// ============================================================
// Test 2: Control Flow (if/else)
// ============================================================
int32_t test_if_else(int32_t x) {
    if (x > 0) return 1;
    else if (x < 0) return -1;
    else return 0;
}

int32_t test_if_nested(int32_t a, int32_t b, int32_t c) {
    if (a > b) {
        if (a > c) return a;
        else return c;
    } else {
        if (b > c) return b;
        else return c;
    }
}

// ============================================================
// Test 3: Loops (while, for, do-while)
// ============================================================
int32_t test_while_loop(int32_t n) {
    int32_t sum = 0;
    int32_t i = 0;
    while (i < n) {
        sum += i;
        i++;
    }
    return sum;
}

int32_t test_for_loop(int32_t n) {
    int32_t sum = 0;
    for (int32_t i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

int32_t test_do_while(int32_t n) {
    int32_t i = 0;
    do {
        i++;
    } while (i < n);
    return i;
}

// ============================================================
// Test 4: Function Calls with Parameters
// ============================================================
int32_t test_call_two_args(int32_t a, int32_t b) {
    return test_add(a, b) + test_mul(a, b);
}

int32_t test_call_four_args(int32_t a, int32_t b, int32_t c, int32_t d) {
    return a + b + c + d;
}

int64_t test_call_eight_args(
    int64_t a, int64_t b, int64_t c, int64_t d,
    int64_t e, int64_t f, int64_t g, int64_t h
) {
    return a + b + c + d + e + f + g + h;
}

// ============================================================
// Test 5: Struct Access
// ============================================================
typedef struct {
    int32_t x;
    int32_t y;
    int64_t z;
} Point;

int32_t test_struct_field_read(Point* p) {
    return p->x + p->y;
}

void test_struct_field_write(Point* p, int32_t v) {
    p->x = v;
    p->y = v * 2;
}

int64_t test_struct_nested_read(Point* p) {
    return p->z;
}

// ============================================================
// Test 6: Stack Variables (force spilling)
// ============================================================
int32_t test_stack_spill(int32_t a, int32_t b, int32_t c, int32_t d,
                         int32_t e, int32_t f, int32_t g, int32_t h,
                         int32_t i, int32_t j, int32_t k, int32_t l) {
    // Force many variables to spill to stack
    int32_t v1 = a + b;
    int32_t v2 = c + d;
    int32_t v3 = e + f;
    int32_t v4 = g + h;
    int32_t v5 = i + j;
    int32_t v6 = k + l;
    int32_t v7 = v1 + v2;
    int32_t v8 = v3 + v4;
    int32_t v9 = v5 + v6;
    return v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9;
}

// ============================================================
// Test 7: Bitfield Operations
// ============================================================
uint32_t test_bitfield_extract(uint32_t x) {
    return (x >> 4) & 0xFF;  // ubfx
}

int32_t test_bitfield_sign_extend(int32_t x) {
    return (x << 20) >> 20;  // sbfx pattern
}

int32_t test_bit_test(int32_t x) {
    if (x & (1 << 3)) return 1;  // tbz/tbnz
    return 0;
}

// ============================================================
// Test 8: Pointer Arithmetic
// ============================================================
int32_t test_ptr_arith(int32_t* arr, int32_t idx) {
    return arr[idx];  // ldr with scaled index
}

void test_ptr_write(int32_t* arr, int32_t idx, int32_t val) {
    arr[idx] = val;
}

int32_t test_ptr_diff(int32_t* a, int32_t* b) {
    return (int32_t)(a - b);
}

// ============================================================
// Test 9: Recursion
// ============================================================
int32_t test_factorial(int32_t n) {
    if (n <= 1) return 1;
    return n * test_factorial(n - 1);
}

// ============================================================
// Test 10: Switch/Case
// ============================================================
int32_t test_switch(int32_t x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        default: return 0;
    }
}

// ============================================================
// Test 11: Load/Store variants
// ============================================================
int8_t test_ldrsb(int8_t* p) { return *p; }
int16_t test_ldrsh(int16_t* p) { return *p; }
int32_t test_ldrsw(int32_t* p) { return *p; }
uint8_t test_ldrb(uint8_t* p) { return *p; }
uint16_t test_ldrh(uint16_t* p) { return *p; }

void test_strb(uint8_t* p, uint8_t v) { *p = v; }
void test_strh(uint16_t* p, uint16_t v) { *p = v; }

// ============================================================
// Test 12: Conditional Select
// ============================================================
int32_t test_csel(int32_t a, int32_t b, int32_t cond) {
    return cond ? a : b;
}

// ============================================================
// Main: call all tests
// ============================================================
volatile int32_t g_result = 0;

int main() {
    g_result = test_add(3, 4);
    g_result = test_sub(10, 3);
    g_result = test_mul(6, 7);
    g_result = test_div_s(100, 5);
    g_result = test_div_u(100, 5);
    g_result = test_mod_s(17, 5);
    g_result = (int32_t)test_mull(100000, 100000);
    g_result = (int32_t)test_umull(100000, 100000);
    g_result = test_neg(42);
    g_result = test_and(0xFF, 0x0F);
    g_result = test_or(0xF0, 0x0F);
    g_result = test_xor(0xFF, 0x0F);
    g_result = test_not(0);
    g_result = test_lsl(1, 5);
    g_result = test_lsr(32, 2);
    g_result = test_asr(-32, 2);

    g_result = test_if_else(5);
    g_result = test_if_else(0);
    g_result = test_if_else(-3);
    g_result = test_if_nested(3, 5, 2);

    g_result = test_while_loop(10);
    g_result = test_for_loop(10);
    g_result = test_do_while(10);

    g_result = test_call_two_args(3, 4);
    g_result = test_call_four_args(1, 2, 3, 4);
    g_result = (int32_t)test_call_eight_args(1, 2, 3, 4, 5, 6, 7, 8);

    Point p = {10, 20, 30};
    g_result = test_struct_field_read(&p);
    test_struct_field_write(&p, 100);
    g_result = (int32_t)test_struct_nested_read(&p);

    g_result = test_stack_spill(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);

    g_result = (int32_t)test_bitfield_extract(0x1234);
    g_result = test_bitfield_sign_extend(0x80000);
    g_result = test_bit_test(0x88);

    int32_t arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    g_result = test_ptr_arith(arr, 5);
    test_ptr_write(arr, 3, 99);

    g_result = test_factorial(5);

    g_result = test_switch(0);
    g_result = test_switch(1);
    g_result = test_switch(2);
    g_result = test_switch(99);

    int8_t sb = -42;
    int16_t sh = -1000;
    int32_t sw = -100000;
    uint8_t ub = 200;
    uint16_t uh = 50000;
    g_result = test_ldrsb(&sb);
    g_result = test_ldrsh(&sh);
    g_result = test_ldrsw(&sw);
    g_result = test_ldrb(&ub);
    g_result = test_ldrh(&uh);

    g_result = test_csel(10, 20, 1);
    g_result = test_csel(10, 20, 0);

    return g_result;
}
