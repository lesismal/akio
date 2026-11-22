/* libbrotli's side of the RFC 9841 shared dictionary cross-check (run.sh): libbrotli built
   with BROTLI_EXPERIMENTAL, dictionaries attached as BROTLI_SHARED_DICTIONARY_SERIALIZED.

     sdtool cases CASES RESULTS      decode records (u32 len, dictionary, u32 len, stream);
                                     write (u8 ok, u32 len, output) per record
     sdtool c DICT QUALITY IN OUT    compress with the dictionary (DICT "-": none)
     sdtool d DICT IN OUT            decompress with the dictionary; exit 1 on error */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <brotli/decode.h>
#include <brotli/encode.h>
#include <brotli/shared_dictionary.h>

static uint8_t* slurp(const char* path, size_t* n) {
  FILE* f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t* b = malloc(len ? (size_t)len : 1);
  if (fread(b, 1, (size_t)len, f) != (size_t)len) { perror(path); exit(2); }
  fclose(f);
  *n = (size_t)len;
  return b;
}

static void spill(const char* path, const uint8_t* b, size_t n) {
  FILE* f = fopen(path, "wb");
  if (!f || fwrite(b, 1, n, f) != n) { perror(path); exit(2); }
  fclose(f);
}

/* Decodes `in` with the serialized dictionary `dict` (none if NULL) into at most `cap` bytes:
   the output length, or -1. */
static long decode(const uint8_t* dict, size_t dlen, const uint8_t* in, size_t n,
                   uint8_t* out, size_t cap) {
  BrotliDecoderState* s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  long r = -1;
  if (dict && !BrotliDecoderAttachDictionary(s, BROTLI_SHARED_DICTIONARY_SERIALIZED, dlen,
                                             dict)) {
    BrotliDecoderDestroyInstance(s);
    return -2;
  }
  size_t avail_in = n, avail_out = cap;
  const uint8_t* next_in = in;
  uint8_t* next_out = out;
  BrotliDecoderResult res =
      BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, NULL);
  if (res == BROTLI_DECODER_RESULT_SUCCESS && avail_in == 0) r = (long)(cap - avail_out);
  BrotliDecoderDestroyInstance(s);
  return r;
}

static uint32_t rd32(const uint8_t* p) {
  return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int main(int argc, char** argv) {
  if (argc >= 4 && !strcmp(argv[1], "cases")) {
    size_t n;
    uint8_t* c = slurp(argv[2], &n);
    FILE* o = fopen(argv[3], "wb");
    size_t cap = 1 << 20, at = 0, cases = 0, okc = 0;
    uint8_t* out = malloc(cap);
    while (at < n) {
      uint32_t dl = rd32(c + at);
      const uint8_t* d = c + at + 4;
      at += 4 + dl;
      uint32_t sl = rd32(c + at);
      const uint8_t* s = c + at + 4;
      at += 4 + sl;
      long r = decode(d, dl, s, sl, out, cap);
      if (r == -2) { fprintf(stderr, "case %zu: dictionary refused\n", cases + 1); return 1; }
      uint8_t ok = r >= 0;
      uint32_t len = ok ? (uint32_t)r : 0;
      uint8_t hdr[5] = {ok, len, len >> 8, len >> 16, len >> 24};
      fwrite(hdr, 1, 5, o);
      fwrite(out, 1, len, o);
      cases++;
      okc += ok;
    }
    fclose(o);
    printf("libbrotli: %zu cases, %zu decoded\n", cases, okc);
    return 0;
  }
  if (argc >= 6 && !strcmp(argv[1], "c")) {
    size_t dl = 0, n;
    uint8_t* d = strcmp(argv[2], "-") ? slurp(argv[2], &dl) : NULL;
    int q = atoi(argv[3]);
    uint8_t* in = slurp(argv[4], &n);
    BrotliEncoderState* s = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, (uint32_t)q);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_LGWIN, 22);
    if (d) {
      BrotliEncoderPreparedDictionary* p = BrotliEncoderPrepareDictionary(
          BROTLI_SHARED_DICTIONARY_SERIALIZED, dl, d, q, NULL, NULL, NULL);
      if (!p || !BrotliEncoderAttachPreparedDictionary(s, p)) {
        fprintf(stderr, "%s: dictionary refused\n", argv[2]);
        return 1;
      }
    }
    size_t cap = n + 1024, avail_in = n, avail_out = cap;
    uint8_t* out = malloc(cap);
    const uint8_t* next_in = in;
    uint8_t* next_out = out;
    if (!BrotliEncoderCompressStream(s, BROTLI_OPERATION_FINISH, &avail_in, &next_in,
                                     &avail_out, &next_out, NULL) ||
        !BrotliEncoderIsFinished(s)) {
      fprintf(stderr, "compression failed\n");
      return 1;
    }
    spill(argv[5], out, cap - avail_out);
    return 0;
  }
  if (argc >= 5 && !strcmp(argv[1], "d")) {
    size_t dl = 0, n;
    uint8_t* d = strcmp(argv[2], "-") ? slurp(argv[2], &dl) : NULL;
    uint8_t* in = slurp(argv[3], &n);
    size_t cap = 64 << 20;
    uint8_t* out = malloc(cap);
    long r = decode(d, dl, in, n, out, cap);
    if (r < 0) { fprintf(stderr, "%s: libbrotli refuses it\n", argv[3]); return 1; }
    spill(argv[4], out, (size_t)r);
    return 0;
  }
  fprintf(stderr, "usage: sdtool cases|c|d ...\n");
  return 2;
}
