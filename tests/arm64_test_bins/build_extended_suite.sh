#!/bin/bash
# Build extended ARM64 test suite - more comprehensive samples
CC=aarch64-linux-gnu-gcc
CFLAGS="-O0 -static"
OUT=/home/ltlly/Code/traceMiku/tests/arm64_test_bins

# === Extended test samples ===

# 1. String operations (memcpy, strlen, strcmp style)
$CC $CFLAGS -o $OUT/test_strings -x c - << 'CEOF'
#include <stdint.h>
int64_t test_strlen(const char* s) { int64_t n=0; while(*s++)n++; return n; }
char* test_strcpy(char* d, const char* s) { char* r=d; while((*d++=*s++)); return r; }
int test_strcmp(const char* a, const char* b) { while(*a&&*a==*b){a++;b++;} return *a-*b; }
void* test_memcpy(void* d, const void* s, int64_t n) { char* cd=d; const char* cs=s; for(int64_t i=0;i<n;i++)cd[i]=cs[i]; return d; }
void* test_memset(void* d, int c, int64_t n) { char* cd=d; for(int64_t i=0;i<n;i++)cd[i]=(char)c; return d; }
int main(){ char buf[100]; test_strlen("hello"); test_strcpy(buf,"world"); test_strcmp("abc","abd"); test_memcpy(buf,buf+1,5); test_memset(buf,0,10); return 0; }
CEOF

# 2. Floating point (if ARM64 supports it)
$CC $CFLAGS -o $OUT/test_fp -x c - << 'CEOF'
double test_fadd(double a, double b) { return a+b; }
double test_fmul(double a, double b) { return a*b; }
float test_faddf(float a, float b) { return a+b; }
int test_fcmp(double a, double b) { if(a>b)return 1; if(a<b)return -1; return 0; }
int main() { test_fadd(1.5,2.5); test_fmul(3.0,4.0); test_fcmp(1.0,2.0); return 0; }
CEOF

# 3. Linked list operations
$CC $CFLAGS -o $OUT/test_linkedlist -x c - << 'CEOF'
#include <stdint.h>
#include <stdlib.h>
typedef struct Node { int val; struct Node* next; } Node;
int test_list_sum(Node* h) { int s=0; while(h){s+=h->val;h=h->next;} return s; }
Node* test_list_reverse(Node* h) { Node*prev=0,*next;while(h){next=h->next;h->next=prev;prev=h;h=next;} return prev; }
int test_list_length(Node* h) { int n=0; while(h){n++;h=h->next;} return n; }
int main() { Node a={1,0},b={2,0},c={3,0}; a.next=&b; b.next=&c; test_list_sum(&a); test_list_reverse(&a); test_list_length(&a); return 0; }
CEOF

# 4. Array/matrix operations
$CC $CFLAGS -o $OUT/test_arrays -x c - << 'CEOF'
#include <stdint.h>
int64_t test_sum_array(int32_t* arr, int n) { int64_t s=0; for(int i=0;i<n;i++) s+=arr[i]; return s; }
void test_bubble_sort(int32_t* arr, int n) { for(int i=0;i<n-1;i++) for(int j=0;j<n-i-1;j++) if(arr[j]>arr[j+1]){int t=arr[j];arr[j]=arr[j+1];arr[j+1]=t;} }
int test_binary_search(int32_t* arr, int n, int k) { int l=0,r=n-1; while(l<=r){int m=(l+r)/2;if(arr[m]==k)return m;if(arr[m]<k)l=m+1;else r=m-1;} return -1; }
int main() { int32_t a[]={5,3,8,1,9}; test_sum_array(a,5); test_bubble_sort(a,5); test_binary_search(a,5,5); return 0; }
CEOF

# 5. Hash / crypto operations
$CC $CFLAGS -o $OUT/test_hash -x c - << 'CEOF'
#include <stdint.h>
uint32_t test_djb2(const char* s) { uint32_t h=5381; int c; while((c=*s++)) h=((h<<5)+h)+c; return h; }
uint32_t test_fnv1a(const uint8_t* d, int n) { uint32_t h=0x811c9dc5; for(int i=0;i<n;i++){h^=d[i];h*=0x01000193;} return h; }
uint32_t test_rotl(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
int main() { test_djb2("hello"); uint8_t d[]={0,1,2,3}; test_fnv1a(d,4); test_rotl(0x12345678,8); return 0; }
CEOF

# 6. State machine
$CC $CFLAGS -o $OUT/test_fsm -x c - << 'CEOF'
typedef enum { S_IDLE, S_RUN, S_DONE, S_ERROR } State;
State test_fsm_next(State s, int event) {
    switch(s) {
        case S_IDLE: return event?S_RUN:S_IDLE;
        case S_RUN: return event==2?S_ERROR:event?S_DONE:S_RUN;
        case S_DONE: return S_IDLE;
        case S_ERROR: return event==0?S_IDLE:S_ERROR;
        default: return S_IDLE;
    }
}
int main() { test_fsm_next(S_IDLE,1); test_fsm_next(S_RUN,2); test_fsm_next(S_DONE,0); return 0; }
CEOF

echo "Extended test suite built:"
ls -la $OUT/test_strings $OUT/test_fp $OUT/test_linkedlist $OUT/test_arrays $OUT/test_hash $OUT/test_fsm 2>/dev/null
