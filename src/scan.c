#include "sift.h"

typedef struct {
    const char *name;
    const unsigned char *pat;
    unsigned len;
} csig_t;

static const unsigned char PAT_AES_SBOX[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5};
static const unsigned char PAT_AES_RCON[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                                             0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};
static const unsigned char PAT_SHA256_K[] = {0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
                                            0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5};
static const unsigned char PAT_SHA256_H0[] = {0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
                                              0x3c, 0x6e, 0xf3, 0x72};
static const unsigned char PAT_MD5_T[] = {0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xbd, 0x91, 0x65,
                                          0xbd, 0x2d, 0x0b, 0xfb};
static const unsigned char PAT_CHACHA[] = {0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
                                          0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b};
static const unsigned char PAT_B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char PAT_HEX[] = "0123456789abcdefABCDEF";
static const unsigned char PAT_PNG_IDAT[] = {0x49, 0x44, 0x41, 0x54, 0x78, 0x9c};
static const unsigned char PAT_ZLIB78[] = {0x78, 0x9c, 0x01, 0x00};
static const unsigned char PAT_UTF8BOM[] = {0xef, 0xbb, 0xbf};

static const csig_t CONSTS[] = {
    {"AES S-box", PAT_AES_SBOX, sizeof(PAT_AES_SBOX)},
    {"AES rcon", PAT_AES_RCON, sizeof(PAT_AES_RCON)},
    {"SHA-256 round constants", PAT_SHA256_K, sizeof(PAT_SHA256_K)},
    {"SHA-256 IV", PAT_SHA256_H0, sizeof(PAT_SHA256_H0)},
    {"MD5 T-table", PAT_MD5_T, sizeof(PAT_MD5_T)},
    {"ChaCha20 sigma", PAT_CHACHA, sizeof(PAT_CHACHA)},
    {"Base64 alphabet", PAT_B64, sizeof(PAT_B64) - 1},
    {"zlib header 78 9c", PAT_ZLIB78, sizeof(PAT_ZLIB78)},
    {"PNG IDAT chunk", PAT_PNG_IDAT, sizeof(PAT_PNG_IDAT)},
    {"UTF-8 BOM", PAT_UTF8BOM, sizeof(PAT_UTF8BOM)}
};

static const csig_t PACKERS[] = {
    {"UPX", (const unsigned char *)"UPX!", 4},
    {"ASPack", (const unsigned char *)"ASPack", 6},
    {"PECompact", (const unsigned char *)"PEC2", 4},
    {"Themida", (const unsigned char *)"Themida", 7},
    {"VMProtect", (const unsigned char *)".vmp0", 5},
    {"PyInstaller", (const unsigned char *)"pyi-", 4},
    {"Nuitka", (const unsigned char *)"__nuitka", 8},
    {"MPRESS", (const unsigned char *)"MPRESS1", 7}
};

static int scan_for(const unsigned char *b, size_t n, const void *pat, size_t plen)
{
    if (!plen || n < plen)
        return 0;
    const unsigned char *p = (const unsigned char *)pat;
    for (size_t i = 0; i + plen <= n; i++)
        if (!memcmp(b + i, p, plen))
            return 1;
    return 0;
}

int vso_is_self(const unsigned char *b, size_t n);

int vso_is_self(const unsigned char *b, size_t n)
{
    static const char *selfpath = 0;
    if (!selfpath) {
        extern char **environ;
        for (char **e = environ; e && *e; e++)
            if (!strncmp(*e, "SIFT_SELF=", 10))
                selfpath = *e + 10;
    }
    if (!selfpath || !*selfpath)
        return 0;
    unsigned char *sb = 0;
    size_t sn = 0;
    if (vso_read_file(selfpath, &sb, &sn) != 0)
        return 0;
    int same = (sn == n && !memcmp(sb, b, n));
    free(sb);
    return same;
}

static const char *LIBPATS[] = {"libc.so", "libm.so", "libdl.so", "libpthread.so", "librt.so",
                                "libstdc++", "libgcc_s", "libcrypto", "libssl", "libcurl",
                                "libz.so", "libsqlite", "libuv", "libpcre", "libxml2", "libjpeg",
                                "libpng", "libtorch", "libgomp", "libpython", "ld-linux",
                                "ld64.so", "libSystem", "libasan", "libubsan", "libmvec",
                                "libquadmath", "libzstd", "libbz2"};
#define N_LIBPAT ((int)(sizeof(LIBPATS) / sizeof(LIBPATS[0])))

int vso_scan_consts(const unsigned char *b, size_t n, sift_t *o)
{
    o->nconsts = 0;
    int self = vso_is_self(b, n);
    if (self)
        return 0;
    for (size_t i = 0; i < sizeof(CONSTS) / sizeof(CONSTS[0]); i++) {
        if (scan_for(b, n, CONSTS[i].pat, CONSTS[i].len)) {
            if (o->nconsts < SIFT_MAX_SIG)
                snprintf(o->consts[o->nconsts++], 64, "%s", CONSTS[i].name);
        }
    }
    for (size_t i = 0; i < sizeof(PACKERS) / sizeof(PACKERS[0]); i++) {
        if (scan_for(b, n, PACKERS[i].pat, PACKERS[i].len)) {
            o->packer = 1;
            o->packer_name = PACKERS[i].name;
            break;
        }
    }
    (void)PAT_HEX;
    return o->nconsts;
}

static int lib_wanted(const char *s)
{
    if (s[0] != 'l' && s[0] != 'L')
        return 0;
    if (strchr(s, ' '))
        return 0;
    for (int i = 0; i < N_LIBPAT; i++)
        if (strstr(s, LIBPATS[i]))
            return 1;
    return 0;
}

int vso_scan_libs(const unsigned char *b, size_t n, sift_t *o)
{
    o->nlibs = 0;
    size_t i = 0;
    while (i < n && o->nlibs < SIFT_MAX_SIG) {
        if (b[i] >= 0x20 && b[i] <= 0x7e) {
            size_t j = i;
            while (j < n && b[j] >= 0x20 && b[j] <= 0x7e)
                j++;
            size_t len = j - i;
            if (len >= 6 && len < 96) {
                char tmp[96];
                size_t c = len < 95 ? len : 95;
                memcpy(tmp, b + i, c);
                tmp[c] = 0;
                if (lib_wanted(tmp)) {
                    int dup = 0;
                    for (int k = 0; k < o->nlibs; k++)
                        if (!strcmp(o->libs[k], tmp))
                            dup = 1;
                    if (!dup)
                        snprintf(o->libs[o->nlibs++], 96, "%s", tmp);
                }
            }
            i = j;
        } else {
            i++;
        }
    }
    return o->nlibs;
}

static int str_interesting(const char *s)
{
    static const char *pats[] = {"http", "ssl", "key", "pass", "token", "auth", "crypt", "hash",
                                 "connect", "socket", "addr", "port", "user", "admin", "root",
                                 "exec", "system", "shell", "eval", "tensor", "layer", "conv",
                                 "grad", "loss", "model", "sql", "select", "query", "error",
                                 "version", "config", "path", "file", "dir", "error", "warning"};
    for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++)
        if (strstr(s, pats[i]))
            return 1;
    return 0;
}

int vso_scan_strings(const unsigned char *b, size_t n, sift_t *o)
{
    o->nstrs = 0;
    size_t i = 0;
    while (i < n && o->nstrs < SIFT_MAX_SIG) {
        if (b[i] >= 0x20 && b[i] <= 0x7e) {
            size_t j = i;
            while (j < n && b[j] >= 0x20 && b[j] <= 0x7e)
                j++;
            size_t len = j - i;
            if (len >= SIFT_STR_MIN && len < 78) {
                char tmp[80];
                size_t c = len < 79 ? len : 79;
                memcpy(tmp, b + i, c);
                tmp[c] = 0;
                if (str_interesting(tmp))
                    snprintf(o->strs[o->nstrs++], 80, "%s", tmp);
            }
            i = j;
        } else {
            i++;
        }
    }
    return o->nstrs;
}
