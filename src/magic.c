#include "sift.h"

const fmt_def_t SIFT_FORMATS[] = {
    {"ELF", FMT_ELF, "systems"},
    {"ELF core", FMT_ELF_CORE, "systems"},
    {"PE32", FMT_PE, "systems"},
    {"Mach-O", FMT_MACH_O, "systems"},
    {"Mach-O fat", FMT_MACH_O_FAT, "systems"},
    {"WebAssembly", FMT_WASM, "web"},
    {"Java class", FMT_JAVA_CLASS, "systems"},
    {".NET assembly", FMT_DOTNET, "systems"},
    {"Python bytecode", FMT_PYTHON_PYC, "systems"},
    {"Lua bytecode", FMT_LUA, "systems"},
    {"ZIP archive", FMT_ZIP, "other"},
    {"gzip", FMT_GZIP, "other"},
    {"bzip2", FMT_BZIP2, "other"},
    {"xz", FMT_XZ, "other"},
    {"tar archive", FMT_TAR, "other"},
    {"PNG image", FMT_PNG, "media"},
    {"JPEG image", FMT_JPEG, "media"},
    {"GIF image", FMT_GIF, "media"},
    {"PDF document", FMT_PDF, "other"},
    {"SQLite database", FMT_SQLITE, "database"},
    {"Dalvik DEX", FMT_DEX, "mobile"},
    {"RIFF container", FMT_RIFF, "media"},
    {"WOFF font", FMT_WOFF, "media"},
    {"COFF object", FMT_COFF, "systems"},
    {"Ostrich/Go pclntab", FMT_OSTRICH, "systems"},
    {"unknown", FMT_NONE, "unknown"}
};

const int SIFT_NFMT = (int)(sizeof(SIFT_FORMATS) / sizeof(SIFT_FORMATS[0]));

const char *inf_fmt_name(uint32_t id)
{
    for (int i = 0; i < SIFT_NFMT; i++)
        if (SIFT_FORMATS[i].id == (fmt_t)id)
            return SIFT_FORMATS[i].name;
    return "unknown";
}

const char *inf_fmt_cat(uint32_t id)
{
    for (int i = 0; i < SIFT_NFMT; i++)
        if (SIFT_FORMATS[i].id == (fmt_t)id)
            return SIFT_FORMATS[i].cat;
    return "unknown";
}

int vso_read_file(const char *path, unsigned char **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0 || sz > (1L << 31)) {
        fclose(f);
        return -1;
    }
    rewind(f);
    unsigned char *b = malloc((size_t)sz + 1);
    if (!b) {
        fclose(f);
        return -1;
    }
    size_t got = sz ? fread(b, 1, (size_t)sz, f) : 0;
    fclose(f);
    if (got != (size_t)sz) {
        free(b);
        return -1;
    }
    b[sz] = 0;
    *buf = b;
    *len = (size_t)sz;
    return 0;
}

static int magic_at(const unsigned char *b, size_t n, size_t off, const char *m, size_t ml)
{
    return off + ml <= n && !memcmp(b + off, m, ml);
}

static int be32(const unsigned char *p)
{
    return (int)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
}

static int le32(const unsigned char *p)
{
    return (int)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static int has_at(const unsigned char *b, size_t n, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || n < nl)
        return 0;
    for (size_t i = 0; i + nl <= n; i++)
        if (!memcmp(b + i, needle, nl))
            return 1;
    return 0;
}

int vso_detect_fmt(const unsigned char *b, size_t n, uint32_t *out, int *bits, int *le, int *is_dyn)
{
    *out = FMT_NONE;
    *bits = 0;
    *le = 1;
    *is_dyn = 0;

    if (magic_at(b, n, 0, "\x7f" "ELF", 4) && n >= 20) {
        *bits = (b[4] == 2) ? 64 : 32;
        *le = (b[5] == 1);
        uint32_t etype = *le ? (uint32_t)(b[16] | (b[17] << 8)) : (uint32_t)((b[16] << 8) | b[17]);
        *is_dyn = (etype == 3);
        *out = (etype == 4) ? FMT_ELF_CORE : FMT_ELF;
        return 0;
    }
    if (magic_at(b, n, 0, "MZ", 2)) {
        *out = FMT_PE;
        return 0;
    }
    if (n >= 4) {
        uint32_t l = le32(b);
        uint32_t bf = be32(b);
        if (l == 0xFEEDFACE || l == 0xFEEDFACF || l == 0xCEFAEDFE || l == 0xCFFAEDFE) {
            *out = FMT_MACH_O;
            *bits = (l == 0xFEEDFACF || l == 0xCFFAEDFE) ? 64 : 32;
            *le = (l == 0xFEEDFACE || l == 0xFEEDFACF);
            return 0;
        }
        if (bf == 0xCAFEBABE || bf == 0xBEBAFECA || bf == 0xCAFEBABF) {
            if (n >= 8 && b[4] == 0x00 && b[5] == 0x00 && b[6] == 0x00 && b[7] == 0x00) {
                *out = FMT_MACH_O_FAT;
                return 0;
            }
            *out = FMT_JAVA_CLASS;
            return 0;
        }
        if (bf == 0xCFFAEDFE || bf == 0xCEFAEDFE) {
            *out = FMT_JAVA_CLASS;
            return 0;
        }
    }
    if (magic_at(b, n, 0, "\0asm", 4)) {
        *out = FMT_WASM;
        return 0;
    }
    if (magic_at(b, n, 0, "BSJB", 4)) {
        *out = FMT_DOTNET;
        return 0;
    }
    if (magic_at(b, n, 0, "\x1bLua", 4)) {
        *out = FMT_LUA;
        return 0;
    }
    if (magic_at(b, n, 0, "dex\n", 4)) {
        *out = FMT_DEX;
        return 0;
    }
    if (magic_at(b, n, 0, "PK\x03\x04", 4)) {
        *out = FMT_ZIP;
        return 0;
    }
    if (magic_at(b, n, 0, "\x1f\x8b", 2)) {
        *out = FMT_GZIP;
        return 0;
    }
    if (magic_at(b, n, 0, "BZh", 3)) {
        *out = FMT_BZIP2;
        return 0;
    }
    if (magic_at(b, n, 0, "\xfd" "7zXZ", 6)) {
        *out = FMT_XZ;
        return 0;
    }
    if (magic_at(b, n, 0, "\x89PNG\r\n\x1a\n", 8)) {
        *out = FMT_PNG;
        return 0;
    }
    if (magic_at(b, n, 0, "\xff\xd8\xff", 3)) {
        *out = FMT_JPEG;
        return 0;
    }
    if (magic_at(b, n, 0, "GIF87a", 6) || magic_at(b, n, 0, "GIF89a", 6)) {
        *out = FMT_GIF;
        return 0;
    }
    if (magic_at(b, n, 0, "%PDF-", 5)) {
        *out = FMT_PDF;
        return 0;
    }
    if (magic_at(b, n, 0, "SQLite format 3\0", 16)) {
        *out = FMT_SQLITE;
        return 0;
    }
    if (magic_at(b, n, 0, "RIFF", 4) && n >= 12 && !memcmp(b + 8, "WEBP", 4)) {
        *out = FMT_RIFF;
        return 0;
    }
    if (magic_at(b, n, 0, "wOFF", 4)) {
        *out = FMT_WOFF;
        return 0;
    }
    if (n >= 2) {
        uint16_t m = (uint16_t)(b[0] | (b[1] << 8));
        if (m == 0x014C || m == 0x8664 || m == 0x01F0 || m == 0x00C0) {
            *out = FMT_COFF;
            *bits = (m == 0x8664) ? 64 : 32;
            return 0;
        }
    }
    if (has_at(b, n, "Go build ID:") || has_at(b, n, "runtime.morestack") ||
        has_at(b, n, "go1.")) {
        *out = FMT_OSTRICH;
        return 0;
    }
    if (n >= 16 && has_at(b, n, "ustar")) {
        *out = FMT_TAR;
        return 0;
    }
    if (n >= 9 && has_at(b, n, "go1.")) {
        *out = FMT_OSTRICH;
        return 0;
    }
    if (n >= 4 && b[0] == 0x0D && b[1] == 0x0A && b[2] == 0x0A && b[3] == 0x0A) {
        *out = FMT_PYTHON_PYC;
        return 0;
    }
    return -1;
}
