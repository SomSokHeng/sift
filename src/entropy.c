#include <math.h>

#include "sift.h"

double inf_entropy(const unsigned char *b, size_t n)
{
    size_t cnt[256];
    size_t tot = 0;
    memset(cnt, 0, sizeof(cnt));
    for (size_t i = 0; i < n; i++) {
        cnt[b[i]]++;
        tot++;
    }
    if (!tot)
        return 0.0;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (cnt[i]) {
            double p = (double)cnt[i] / (double)tot;
            h -= p * log2(p);
        }
    }
    return h;
}

#define WIN 1024

int inf_hi_entropy(const unsigned char *b, size_t n, double *out)
{
    if (n < WIN) {
        *out = 0.0;
        return 0;
    }
    double worst = 0.0;
    size_t step = WIN;
    for (size_t off = 0; off + WIN <= n; off += step) {
        double h = inf_entropy(b + off, WIN);
        if (h > worst)
            worst = h;
        if (worst > 8.0)
            break;
    }
    *out = worst;
    return 1;
}

static uint32_t rd16(const unsigned char *p, int le)
{
    return le ? (uint32_t)(p[0] | (p[1] << 8)) : (uint32_t)(p[0] << 8 | p[1]);
}

static uint32_t rd32(const unsigned char *p, int le)
{
    if (le)
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t rd64(const unsigned char *p, int le)
{
    if (le)
        return (uint64_t)rd32(p, 1) | ((uint64_t)rd32(p + 4, 1) << 32);
    return ((uint64_t)rd32(p, 0) << 32) | (uint64_t)rd32(p + 4, 0);
}

static const char *arch_name(uint16_t m)
{
    switch (m) {
    case 3: return "x86";
    case 8: return "mips";
    case 20: return "ppc";
    case 21: return "ppc64";
    case 40: return "arm";
    case 62: return "x86_64";
    case 183: return "aarch64";
    case 243: return "riscv";
    case 0x16c: return "mips64";
    default: return "unknown";
    }
}

static void arch_from_elf(uint16_t m, char *out, size_t osz)
{
    snprintf(out, osz, "%s", arch_name(m));
}

static int has_byte_run(const unsigned char *b, size_t n, const char *needle, size_t nl)
{
    if (!nl || n < nl)
        return 0;
    for (size_t i = 0; i + nl <= n; i++)
        if (!memcmp(b + i, needle, nl))
            return 1;
    return 0;
}

int vso_elf_parse(unsigned char *b, size_t n, sift_t *o)
{
    if (n < 64)
        return -1;
    int is64 = (b[4] == 2);
    int le = (b[5] == 1);
    o->bits = is64 ? 64 : 32;
    o->is_le = le;
    o->etype = (uint16_t)rd16(b + 16, le);
    o->machine = (uint16_t)rd16(b + 18, le);
    o->is_dyn = (o->etype == 3);
    o->has_pie = (o->etype == 3);
    arch_from_elf(o->machine, o->arch, sizeof(o->arch));

    uint64_t shoff;
    uint16_t shentsize, shnum, shstrndx;
    if (is64) {
        o->entry = rd64(b + 24, le);
        shoff = rd64(b + 40, le);
        shentsize = rd16(b + 58, le);
        shnum = rd16(b + 60, le);
        shstrndx = rd16(b + 62, le);
    } else {
        o->entry = rd32(b + 24, le);
        shoff = rd32(b + 32, le);
        shentsize = rd16(b + 46, le);
        shnum = rd16(b + 48, le);
        shstrndx = rd16(b + 50, le);
    }
    o->nsec = shnum;
    o->stripped = 1;

    size_t phoff, phentsize, phnum;
    if (is64) {
        phoff = (size_t)rd64(b + 32, le);
        phentsize = rd16(b + 54, le);
        phnum = rd16(b + 56, le);
    } else {
        phoff = rd32(b + 28, le);
        phentsize = rd16(b + 42, le);
        phnum = rd16(b + 44, le);
    }
    if (phoff && phnum && phentsize >= 32) {
        for (size_t i = 0; i < phnum; i++) {
            size_t o2 = phoff + i * phentsize;
            if (o2 + phentsize > n)
                break;
            uint32_t ptype = rd32(b + o2, le);
            if (ptype == 0x6474e551) {
                o->has_relro = 1;
            } else if (ptype == 0x6474e552) {
                uint32_t fl = is64 ? rd32(b + o2 + 4, le) : rd32(b + o2 + 24, le);
                o->has_nx = (fl & 0x1) ? 0 : 1;
            }
        }
    }

    if (!shoff || !shnum || shstrndx >= shnum)
        return 0;
    if ((size_t)shoff + (size_t)shnum * shentsize > n)
        return 0;

    unsigned char *shstr = b + shoff + (size_t)shstrndx * shentsize;
    uint64_t stroff = is64 ? rd64(shstr + 24, le) : rd32(shstr + 16, le);
    if (stroff >= n)
        return 0;
    const char *shstrtab = (const char *)(b + stroff);

    for (uint16_t i = 0; i < shnum; i++) {
        unsigned char *sh = b + shoff + (size_t)i * shentsize;
        uint32_t shtype = rd32(sh + 4, le);
        uint64_t off, size;
        uint32_t nameoff = rd32(sh, le);
        if (is64) {
            off = rd64(sh + 24, le);
            size = rd64(sh + 32, le);
        } else {
            off = rd32(sh + 16, le);
            size = rd32(sh + 20, le);
        }
        const char *nm = (stroff + nameoff < n) ? shstrtab + nameoff : "?";
        if (shtype == 2) {
            o->stripped = 0;
            o->nsym = size / (is64 ? 24 : 16);
        } else if (shtype == 1 && !strcmp(nm, ".interp")) {
            if (off + size <= n && size > 0) {
                size_t lim = size < sizeof(o->interp) - 1 ? size : sizeof(o->interp) - 1;
                memcpy(o->interp, b + off, lim);
                o->interp[lim] = 0;
            }
        } else if (shtype == 6) {
            uint16_t step = is64 ? 16 : 8;
            for (uint64_t k = 0; off + k + step <= n && k < size; k += step) {
                uint64_t tag = is64 ? rd64(b + off + k, le) : rd32(b + off + k, le);
                if (!tag)
                    break;
            }
        } else if (shtype == 11) {
            uint64_t esz = is64 ? 24 : 16;
            o->nsym += size / esz;
        }
    }

    o->has_canary = has_byte_run(b, n, "__stack_chk_fail", 16);
    return 0;
}

int vso_pe_parse(unsigned char *b, size_t n, sift_t *o)
{
    if (n < 0x40)
        return -1;
    uint32_t peoff = (uint32_t)rd32(b + 0x3c, 1);
    if ((size_t)peoff + 24 > n)
        return -1;
    if (memcmp(b + peoff, "PE\0\0", 4))
        return -1;
    uint16_t machine = (uint16_t)rd16(b + peoff + 4, 1);
    uint16_t nsec = (uint16_t)rd16(b + peoff + 6, 1);
    uint16_t optsz = (uint16_t)rd16(b + peoff + 20, 1);
    uint32_t chars = rd32(b + peoff + 22, 1) & 0xFFFF;
    uint16_t optmagic = (uint16_t)rd16(b + peoff + 24, 1);
    int is64 = (optmagic == 0x20b);

    o->bits = is64 ? 64 : 32;
    o->is_le = 1;
    o->machine = machine;
    o->etype = (uint16_t)(is64 ? 3 : 2);
    o->has_nx = (chars & 0x0100) ? 1 : 0;
    o->has_canary = (chars & 0x4000) ? 1 : 0;
    o->has_relro = 0;
    o->has_pie = (chars & 0x0020) ? 1 : 0;
    o->nsec = nsec;
    snprintf(o->arch, sizeof(o->arch), "%s", arch_name(machine));
    o->is_dyn = 1;

    uint32_t certoff = 0, certsz = 0;
    if (optsz >= 144) {
        uint32_t dd = (uint32_t)rd32(b + peoff + 24 + 128, 1);
        uint32_t cso = (uint32_t)rd32(b + peoff + 24 + 132, 1);
        if (cso > 0) {
            certoff = dd;
            certsz = cso;
        }
    }
    o->is_signed = (certsz > 0 && certoff + certsz <= n);
    if (o->is_signed)
        snprintf(o->buildid, sizeof(o->buildid), "authenticode %u bytes", certsz);

    return 0;
}
