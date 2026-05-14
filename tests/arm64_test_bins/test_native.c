// Native ARM64 .so for Android real-device testing
// Compile: aarch64-linux-gnu-gcc -fPIC -shared -O0 -o libtest.so test_native.c
#include <stdint.h>
#include <string.h>

// Algorithm 1: SHA-256 (simplified)
static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t rotr(uint32_t x, int n) { return (x>>n)|(x<<(32-n)); }
static uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(~x&z);}
static uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}
static uint32_t S0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
static uint32_t S1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
static uint32_t s0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
static uint32_t s1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}

void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64], a[8];
    for(int i=0;i<16;i++) w[i]=(block[i*4]<<24)|(block[i*4+1]<<16)|(block[i*4+2]<<8)|block[i*4+3];
    for(int i=16;i<64;i++) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    for(int i=0;i<8;i++) a[i]=state[i];
    for(int i=0;i<64;i++){
        uint32_t t1=a[7]+S1(a[4])+Ch(a[4],a[5],a[6])+K[i]+w[i];
        uint32_t t2=S0(a[0])+Maj(a[0],a[1],a[2]);
        a[7]=a[6];a[6]=a[5];a[5]=a[4];a[4]=a[3]+t1;a[3]=a[2];a[2]=a[1];a[1]=a[0];a[0]=t1+t2;
    }
    for(int i=0;i<8;i++) state[i]+=a[i];
}

// Algorithm 2: Base64 encode (real implementation)
static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int base64_enc(const uint8_t* in, int len, char* out){
    int o=0;
    for(int i=0;i<len;i+=3){
        uint32_t v=((uint32_t)(in[i])<<16)|((i+1<len?(uint32_t)in[i+1]:0)<<8)|(i+2<len?in[i+2]:0);
        out[o++]=B64[(v>>18)&63]; out[o++]=B64[(v>>12)&63];
        out[o++]=i+1<len?B64[(v>>6)&63]:'='; out[o++]=i+2<len?B64[v&63]:'=';
    }
    out[o]=0; return o;
}

// Algorithm 3: RC4
void rc4_cipher(uint8_t* S, uint8_t* data, int len){
    int i=0,j=0;
    for(int k=0;k<len;k++){
        i=(i+1)&255; j=(j+S[i])&255;
        uint8_t t=S[i]; S[i]=S[j]; S[j]=t;
        data[k]^=S[(S[i]+S[j])&255];
    }
}
void rc4_init(uint8_t* S, const uint8_t* key, int klen){
    for(int i=0;i<256;i++) S[i]=i; int j=0;
    for(int i=0;i<256;i++){j=(j+S[i]+key[i%klen])&255;uint8_t t=S[i];S[i]=S[j];S[j]=t;}
}

// Algorithm 4: DJB2 hash
uint64_t djb2_hash(const uint8_t* data, int len){
    uint64_t h=5381;
    for(int i=0;i<len;i++) h=((h<<5)+h)+data[i];
    return h;
}

// Algorithm 5: Merge sort
void merge(int* a, int l, int m, int r){
    int n1=m-l+1,n2=r-m;
    int L[256],R[256];
    for(int i=0;i<n1;i++) L[i]=a[l+i];
    for(int i=0;i<n2;i++) R[i]=a[m+1+i];
    int i=0,j=0,k=l;
    while(i<n1&&j<n2){if(L[i]<=R[j])a[k++]=L[i++];else a[k++]=R[j++];}
    while(i<n1)a[k++]=L[i++]; while(j<n2)a[k++]=R[j++];
}
void merge_sort(int* a, int l, int r){
    if(l<r){int m=l+(r-l)/2;merge_sort(a,l,m);merge_sort(a,m+1,r);merge(a,l,m,r);}
}

// Entry: exported for Frida tracing
int run_native_test(int mode){
    uint8_t buf[256]; int arr[10]={5,2,8,1,9,3,7,4,6,0};
    switch(mode){
        case 0: { // SHA-256
            uint32_t st[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
            memset(buf,0,64); sha256_transform(st,buf);
            return st[0]&0xff;
        }
        case 1: { char o[32]; return base64_enc((uint8_t*)"hello",5,o); }
        case 2: { uint8_t S[256]; rc4_init(S,(uint8_t*)"key",3); uint8_t d[]="test"; rc4_cipher(S,d,4); return d[0]; }
        case 3: return djb2_hash((uint8_t*)"hello",5)&0xff;
        case 4: merge_sort(arr,0,9); return arr[0];
        default: return mode;
    }
}
