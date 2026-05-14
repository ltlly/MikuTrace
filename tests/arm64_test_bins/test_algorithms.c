// Comprehensive algorithm test suite for ARM64 decompiler
// Cross-compile: aarch64-linux-gnu-gcc -O0 -static -o test_algorithms test_algorithms.c
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ============================================================
// 1. AES-128 (simplified — key expansion + encrypt)
// ============================================================
static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const uint8_t rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

void aes_key_expansion(const uint8_t* key, uint8_t* w) {
    for(int i=0;i<16;i++) w[i]=key[i];
    for(int i=4;i<44;i++){
        uint8_t t[4];
        for(int j=0;j<4;j++) t[j]=w[(i-1)*4+j];
        if(i%4==0){
            uint8_t tmp=t[0]; t[0]=sbox[t[1]]^rcon[i/4]; t[1]=sbox[t[2]]; t[2]=sbox[t[3]]; t[3]=sbox[tmp];
        }
        for(int j=0;j<4;j++) w[i*4+j]=w[(i-4)*4+j]^t[j];
    }
}

void aes_add_round_key(uint8_t* s, const uint8_t* k){for(int i=0;i<16;i++) s[i]^=k[i];}
void aes_sub_bytes(uint8_t* s){for(int i=0;i<16;i++) s[i]=sbox[s[i]];}

void aes_shift_rows(uint8_t* s){
    uint8_t t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; uint8_t u=s[6]; s[6]=s[14]; s[14]=t; s[10]=u;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
uint8_t xtime(uint8_t x){return (x<<1)^((x>>7)?0x1b:0);}
void aes_mix_columns(uint8_t* s){
    for(int i=0;i<4;i++){
        uint8_t a=s[i*4],b=s[i*4+1],c=s[i*4+2],d=s[i*4+3];
        s[i*4]=xtime(a)^xtime(b)^b^c^d; s[i*4+1]=a^xtime(b)^xtime(c)^c^d;
        s[i*4+2]=a^b^xtime(c)^xtime(d)^d; s[i*4+3]=xtime(a)^a^b^xtime(d)^c;
    }
}

void aes128_encrypt(const uint8_t* in, uint8_t* out, const uint8_t* key){
    uint8_t w[176], s[16];
    aes_key_expansion(key,w);
    memcpy(s,in,16);
    aes_add_round_key(s,w);
    for(int r=1;r<10;r++){
        aes_sub_bytes(s); aes_shift_rows(s); aes_mix_columns(s);
        aes_add_round_key(s,w+r*16);
    }
    aes_sub_bytes(s); aes_shift_rows(s); aes_add_round_key(s,w+160);
    memcpy(out,s,16);
}

// ============================================================
// 2. Base64 Encode/Decode
// ============================================================
static const char b64t[64]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int base64_encode(const uint8_t* in, int len, char* out){
    int o=0;
    for(int i=0;i<len;i+=3){
        uint32_t v=((uint32_t)in[i]<<16)|((i+1<len?(uint32_t)in[i+1]:0)<<8)|(i+2<len?in[i+2]:0);
        out[o++]=b64t[(v>>18)&0x3f]; out[o++]=b64t[(v>>12)&0x3f];
        out[o++]=i+1<len?b64t[(v>>6)&0x3f]:'=';
        out[o++]=i+2<len?b64t[v&0x3f]:'=';
    }
    out[o]=0; return o;
}

// ============================================================
// 3. RC4 Stream Cipher
// ============================================================
void rc4_init(uint8_t* S, const uint8_t* key, int klen){
    for(int i=0;i<256;i++) S[i]=i;
    int j=0;
    for(int i=0;i<256;i++){j=(j+S[i]+key[i%klen])&0xff; uint8_t t=S[i]; S[i]=S[j]; S[j]=t;}
}
void rc4_crypt(uint8_t* S, uint8_t* data, int len){
    int i=0,j=0;
    for(int k=0;k<len;k++){
        i=(i+1)&0xff; j=(j+S[i])&0xff;
        uint8_t t=S[i]; S[i]=S[j]; S[j]=t;
        data[k]^=S[(S[i]+S[j])&0xff];
    }
}

// ============================================================
// 4. CRC32
// ============================================================
uint32_t crc32(const uint8_t* data, int len){
    uint32_t crc=0xffffffff;
    for(int i=0;i<len;i++){
        crc^=data[i];
        for(int j=0;j<8;j++) crc=(crc>>1)^(crc&1?0xedb88320:0);
    }
    return crc^0xffffffff;
}

// ============================================================
// 5. QuickSort
// ============================================================
void quicksort(int32_t* a, int lo, int hi){
    if(lo>=hi) return;
    int p=a[(lo+hi)/2],i=lo-1,j=hi+1;
    while(1){
        while(a[++i]<p);
        while(a[--j]>p);
        if(i>=j) break;
        int t=a[i]; a[i]=a[j]; a[j]=t;
    }
    quicksort(a,lo,j); quicksort(a,j+1,hi);
}

// ============================================================
// 6. Binary Search Tree
// ============================================================
typedef struct Bst { int key; struct Bst *l,*r; } Bst;
Bst* bst_insert(Bst* root, int key){
    if(!root){ Bst* n=malloc(sizeof(Bst)); n->key=key; n->l=n->r=0; return n; }
    if(key<root->key) root->l=bst_insert(root->l,key);
    else root->r=bst_insert(root->r,key);
    return root;
}
Bst* bst_search(Bst* root, int key){
    if(!root||root->key==key) return root;
    return key<root->key?bst_search(root->l,key):bst_search(root->r,key);
}
int bst_height(Bst* root){
    if(!root) return 0;
    int lh=bst_height(root->l),rh=bst_height(root->r);
    return 1+(lh>rh?lh:rh);
}

// ============================================================
// 7. Simple Regex Match (* and ? only)
// ============================================================
int match_pattern(const char* p, const char* s){
    if(!*p) return !*s;
    if(*p=='*') return match_pattern(p+1,s)||(*s&&match_pattern(p,s+1));
    if(*p=='?'||*p==*s) return *s&&match_pattern(p+1,s+1);
    return 0;
}

// ============================================================
// 8. LZ77 Simple Compress
// ============================================================
int lz77_compress(const uint8_t* in, int len, uint8_t* out){
    int op=0;
    for(int i=0;i<len;){
        int best_len=0,best_off=0;
        for(int j=i-1;j>=0&&j>=i-255;j--){
            int k=0;
            while(i+k<len&&in[j+k]==in[i+k]&&k<255) k++;
            if(k>best_len){best_len=k;best_off=i-j;}
        }
        if(best_len>=3){out[op++]=best_off; out[op++]=best_len; i+=best_len;}
        else {out[op++]=0; out[op++]=in[i]; i++;}
    }
    return op;
}

// ============================================================
// 9. Huffman Coding (frequency counting)
// ============================================================
void huffman_freq(const uint8_t* data, int len, uint32_t freq[256]){
    memset(freq,0,256*4);
    for(int i=0;i<len;i++) freq[data[i]]++;
}

// ============================================================
// 10. Integer sqrt (Newton's method)
// ============================================================
int32_t isqrt(int32_t n){
    if(n<0) return -1;
    int32_t x=n,y=(x+1)/2;
    while(y<x){x=y;y=(x+n/x)/2;}
    return x;
}

// ============================================================
// 11. GCD / LCM
// ============================================================
int32_t gcd(int32_t a, int32_t b){ return b?gcd(b,a%b):a; }
int32_t lcm(int32_t a, int32_t b){ return a/gcd(a,b)*b; }

// ============================================================
// 12. Fibonacci (iterative + recursive)
// ============================================================
int64_t fib_iter(int n){ int64_t a=0,b=1; for(int i=0;i<n;i++){int64_t t=a+b;a=b;b=t;} return a; }
int64_t fib_rec(int n){ return n<=1?n:fib_rec(n-1)+fib_rec(n-2); }

// ============================================================
// Main — exercise all algorithms
// ============================================================
volatile int g_check = 0;
int main(){
    // AES-128
    uint8_t aes_in[16]="hello world!!!!",aes_out[16],aes_key[16]="1234567890abcdef";
    aes128_encrypt(aes_in,aes_out,aes_key); g_check+=aes_out[0];

    // Base64
    char b64[32]; base64_encode((uint8_t*)"Hello",5,b64); g_check+=b64[0];

    // RC4
    uint8_t S[256],rc4_data[]="secret"; rc4_init(S,(uint8_t*)"key",3); rc4_crypt(S,rc4_data,6); g_check+=rc4_data[0];

    // CRC32
    g_check+=crc32((uint8_t*)"test",4)&0xff;

    // QuickSort
    int32_t arr[]={5,2,8,1,9,3,7}; quicksort(arr,0,6); g_check+=arr[0];

    // BST
    Bst* root=0; root=bst_insert(root,5); bst_insert(root,3); bst_insert(root,8);
    g_check+=(bst_search(root,3)!=0); g_check+=bst_height(root);

    // Pattern match
    g_check+=match_pattern("h*o","hello"); g_check+=match_pattern("a?c","abc");

    // LZ77
    uint8_t lz77_out[100]; g_check+=lz77_compress((uint8_t*)"ABABABABA",9,lz77_out);

    // Huffman
    uint32_t hfreq[256]; huffman_freq((uint8_t*)"aabbc",5,hfreq); g_check+=hfreq['a'];

    // Integer sqrt
    g_check+=isqrt(100);

    // GCD/LCM
    g_check+=gcd(48,18); g_check+=lcm(12,18);

    // Fibonacci
    g_check+=(int)fib_iter(10); g_check+=(int)fib_rec(10);

    return g_check;
}
