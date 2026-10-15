#ifndef SIFT_H
#define SIFT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VSO_TOOL_VER "1.0.0"
#define SIFT_PATH_MAX 4096
#define SIFT_MAX_FMT 32
#define SIFT_MAX_HIT 512
#define SIFT_MAX_SIG 256
#define SIFT_STR_MIN 6
#define SIFT_HASH_HEX 65

typedef enum {
    FMT_NONE = 0,
    FMT_ELF,
    FMT_ELF_CORE,
    FMT_PE,
    FMT_MACH_O,
    FMT_MACH_O_FAT,
    FMT_WASM,
    FMT_JAVA_CLASS,
    FMT_DOTNET,
    FMT_PYTHON_PYC,
    FMT_LUA,
    FMT_ZIP,
    FMT_GZIP,
    FMT_BZIP2,
    FMT_XZ,
    FMT_TAR,
    FMT_PNG,
    FMT_JPEG,
    FMT_GIF,
    FMT_PDF,
    FMT_SQLITE,
    FMT_DEX,
    FMT_RIFF,
    FMT_WOFF,
    FMT_COFF,
    FMT_OSTRICH
} fmt_t;

typedef struct {
    const char *name;
    fmt_t id;
    const char *cat;
} fmt_def_t;

typedef struct {
    char label[SIFT_PATH_MAX];
    char sha256[SIFT_HASH_HEX];
    char sha1[41];
    char md5[33];
    uint64_t size;
    double entropy;
    double hi_entropy;
    uint32_t fmt;
    int bits;
    int is_le;
    int is_dyn;
    uint16_t machine;
    uint16_t etype;
    uint64_t nsym;
    uint64_t nsec;
    uint64_t entry;
    char buildid[96];
    char interp[SIFT_PATH_MAX];
    char arch[32];
    int stripped;
    int has_nx;
    int has_pie;
    int has_canary;
    int has_relro;
    int is_signed;
    int packer;
    const char *packer_name;
    int dom[16];
    int ndom;
    char top[32];
    double top_conf;
    char strs[SIFT_MAX_SIG][80];
    int nstrs;
    char consts[SIFT_MAX_SIG][64];
    int nconsts;
    char libs[SIFT_MAX_SIG][96];
    int nlibs;
} sift_t;

extern const fmt_def_t SIFT_FORMATS[];
extern const int SIFT_NFMT;

const char *inf_fmt_name(uint32_t id);
const char *inf_fmt_cat(uint32_t id);
int vso_read_file(const char *path, unsigned char **buf, size_t *len);
int vso_detect_fmt(const unsigned char *b, size_t n, uint32_t *out, int *bits, int *le, int *is_dyn);
int vso_elf_parse(unsigned char *b, size_t n, sift_t *o);
int vso_pe_parse(unsigned char *b, size_t n, sift_t *o);
int vso_scan_consts(const unsigned char *b, size_t n, sift_t *o);
int vso_is_self(const unsigned char *b, size_t n);
int vso_scan_strings(const unsigned char *b, size_t n, sift_t *o);
int vso_scan_libs(const unsigned char *b, size_t n, sift_t *o);
int inf_classify(sift_t *o);
double inf_entropy(const unsigned char *b, size_t n);
int inf_hi_entropy(const unsigned char *b, size_t n, double *out);
int vso_grade(sift_t *o);
int vso_print(const sift_t *o, FILE *f);
int vso_json(const sift_t *o, FILE *f);
int vso_csv(const sift_t *o, FILE *f);
void vso_usage(FILE *f);
void vso_hash(const unsigned char *b, size_t n, char *s256, char *s1, char *m5);

#endif
