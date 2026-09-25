/* Benchmark of NIST PQC primitives (FIPS 203 ML-KEM-512, FIPS 204 ML-DSA-44)
 * used for the PQC baseline row of Table 6.  Build:
 *   gcc -O2 bench_pqc.c -loqs -o bench_pqc && ./bench_pqc
 */
#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define N 1000
static double now_ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e3+t.tv_nsec/1e6;}
int main(void){
  OQS_KEM *k=OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
  OQS_SIG *s=OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
  if(!k||!s){fprintf(stderr,"alg not enabled\n");return 1;}
  uint8_t pk[k->length_public_key],sk[k->length_secret_key],ct[k->length_ciphertext],ss1[32],ss2[32];
  uint8_t spk[s->length_public_key],ssk[s->length_secret_key],sig[s->length_signature],msg[64]={0};
  size_t siglen; double t,kg=0,enc=0,dec=0,sg=0,vf=0;
  for(int i=0;i<N;i++){
    t=now_ms();OQS_KEM_keypair(k,pk,sk);kg+=now_ms()-t;
    t=now_ms();OQS_KEM_encaps(k,ct,ss1,pk);enc+=now_ms()-t;
    t=now_ms();OQS_KEM_decaps(k,ss2,ct,sk);dec+=now_ms()-t;
  }
  OQS_SIG_keypair(s,spk,ssk);
  for(int i=0;i<N;i++){
    msg[0]=(uint8_t)i;
    t=now_ms();OQS_SIG_sign(s,sig,&siglen,msg,64,ssk);sg+=now_ms()-t;
    t=now_ms();OQS_SIG_verify(s,msg,64,sig,siglen,spk);vf+=now_ms()-t;
  }
  printf("ML-KEM-512: pk=%zu B ct=%zu B | KeyGen=%.4f Encaps=%.4f Decaps=%.4f ms\n",k->length_public_key,k->length_ciphertext,kg/N,enc/N,dec/N);
  printf("ML-DSA-44 : pk=%zu B sig=%zu B | Sign=%.4f Verify=%.4f ms\n",s->length_public_key,s->length_signature,sg/N,vf/N);
  /* PQC baseline mirroring the 4-message three-party flow (see README):
     2 KeyGen + 2 Encaps + 2 Decaps + 4 Sign + 4 Verify */
  printf("PQC baseline total computation = %.3f ms\n",2*kg/N+2*enc/N+2*dec/N+4*sg/N+4*vf/N);
  printf("PQC baseline total communication = %zu bits (+4x32-bit timestamps)\n",
     8*(2*(k->length_public_key+s->length_signature)+2*(k->length_ciphertext+s->length_signature)));
  OQS_KEM_free(k);OQS_SIG_free(s);return 0;}
