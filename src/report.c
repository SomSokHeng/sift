#include "sift.h"

const char *inf_dom_name(int id);

static void jv(FILE *f, const char *v)
{
    if (!v) {
        fprintf(f, "null");
        return;
    }
    fputc('"', f);
    for (const char *p = v; *p; p++) {
        if (*p == '"' || *p == '\\')
            fprintf(f, "\\%c", *p);
        else if ((unsigned char)*p < 0x20)
            fprintf(f, "\\u%04x", (unsigned char)*p);
        else
            fputc(*p, f);
    }
    fputc('"', f);
}

static void jk(FILE *f, const char *k, const char *v)
{
    fprintf(f, "\"%s\":", k);
    jv(f, v);
}

static void jarr(FILE *f, const char (*a)[96], int n)
{
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i)
            fputc(',', f);
        jv(f, a[i]);
    }
    fputc(']', f);
}

static void jarr64(FILE *f, const char (*a)[64], int n)
{
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i)
            fputc(',', f);
        jv(f, a[i]);
    }
    fputc(']', f);
}

static void jarr80(FILE *f, const char (*a)[80], int n)
{
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i)
            fputc(',', f);
        jv(f, a[i]);
    }
    fputc(']', f);
}

int vso_print(const sift_t *o, FILE *f)
{
    fprintf(f, "file       %s\n", o->label);
    fprintf(f, "format     %s  [%s]\n", inf_fmt_name(o->fmt), inf_fmt_cat(o->fmt));
    if (o->bits)
        fprintf(f, "arch       %s %d-bit %s-endian\n", o->arch, o->bits,
                o->is_le ? "little" : "big");
    fprintf(f, "size       %llu bytes\n", (unsigned long long)o->size);
    fprintf(f, "entropy    %.3f (peak window %.3f)\n", o->entropy, o->hi_entropy);
    if (o->nsec)
        fprintf(f, "sections   %llu\n", (unsigned long long)o->nsec);
    if (o->nsym)
        fprintf(f, "symbols    %llu%s\n", (unsigned long long)o->nsym,
                o->stripped ? " (stripped)" : "");
    if (o->entry)
        fprintf(f, "entry      0x%llx\n", (unsigned long long)o->entry);
    if (o->interp[0])
        fprintf(f, "interp     %s\n", o->interp);
    if (o->buildid[0])
        fprintf(f, "buildid    %s\n", o->buildid);
    fprintf(f, "hardening  nx=%s pie=%s canary=%s relro=%s signed=%s\n",
            o->has_nx ? "y" : "n", o->has_pie ? "y" : "n", o->has_canary ? "y" : "n",
            o->has_relro ? "y" : "n", o->is_signed ? "y" : "n");
    if (o->packer)
        fprintf(f, "packer     %s\n", o->packer_name);
    fprintf(f, "domain     %s (confidence %.2f)\n", o->top, o->top_conf);
    fprintf(f, "grade      %d/100\n", vso_grade((sift_t *)o));
    if (o->nlibs) {
        fprintf(f, "libs\n");
        for (int i = 0; i < o->nlibs; i++)
            fprintf(f, "  %s\n", o->libs[i]);
    }
    if (o->nconsts) {
        fprintf(f, "constants\n");
        for (int i = 0; i < o->nconsts; i++)
            fprintf(f, "  %s\n", o->consts[i]);
    }
    fprintf(f, "sha256     %s\n", o->sha256);
    fprintf(f, "sha1       %s\n", o->sha1);
    fprintf(f, "md5        %s\n", o->md5);
    return 0;
}

int vso_json(const sift_t *o, FILE *f)
{
    fprintf(f, "{\n  ");
    jk(f, "file", o->label);
    fprintf(f, ",\n  ");
    jk(f, "format", inf_fmt_name(o->fmt));
    fprintf(f, ",\n  ");
    jk(f, "format_category", inf_fmt_cat(o->fmt));
    fprintf(f, ",\n  ");
    jk(f, "arch", o->arch);
    fprintf(f, ",\n  \"bits\":%d,\n", o->bits);
    fprintf(f, "  \"endian\":\"%s\",\n", o->is_le ? "little" : "big");
    fprintf(f, "  \"size\":%llu,\n", (unsigned long long)o->size);
    fprintf(f, "  \"entropy\":%.4f,\n  \"entropy_peak\":%.4f,\n", o->entropy, o->hi_entropy);
    fprintf(f, "  \"nsec\":%llu,\n  \"nsym\":%llu,\n  \"stripped\":%s,\n",
            (unsigned long long)o->nsec, (unsigned long long)o->nsym, o->stripped ? "true" : "false");
    fprintf(f, "  \"entry\":%llu,\n", (unsigned long long)o->entry);
    fprintf(f, "  ");
    jk(f, "interpreter", o->interp[0] ? o->interp : NULL);
    fprintf(f, ",\n  ");
    jk(f, "buildid", o->buildid[0] ? o->buildid : NULL);
    fprintf(f, ",\n  \"hardening\":{\"nx\":%s,\"pie\":%s,\"canary\":%s,\"relro\":%s,\"signed\":%s},\n",
            o->has_nx ? "true" : "false", o->has_pie ? "true" : "false",
            o->has_canary ? "true" : "false", o->has_relro ? "true" : "false",
            o->is_signed ? "true" : "false");
    fprintf(f, "  \"packer\":%s,\n  ", o->packer ? "true" : "false");
    jk(f, "packer_name", o->packer ? o->packer_name : NULL);
    fprintf(f, ",\n  ");
    jk(f, "domain", o->top);
    fprintf(f, ",\n  \"domain_confidence\":%.4f,\n", o->top_conf);
    fprintf(f, "  \"grade\":%d,\n", vso_grade((sift_t *)o));
    fprintf(f, "  \"libs\":");
    jarr(f, o->libs, o->nlibs);
    fprintf(f, ",\n  \"constants\":");
    jarr64(f, o->consts, o->nconsts);
    fprintf(f, ",\n  \"strings\":");
    jarr80(f, o->strs, o->nstrs);
    fprintf(f, ",\n  ");
    jk(f, "sha256", o->sha256);
    fprintf(f, ",\n  ");
    jk(f, "sha1", o->sha1);
    fprintf(f, ",\n  ");
    jk(f, "md5", o->md5);
    fprintf(f, "\n}\n");
    return 0;
}

int vso_csv(const sift_t *o, FILE *f)
{
    fprintf(f, "file,format,category,arch,bits,size,entropy,entropy_peak,packer,domain,confidence,grade,sha256\n");
    fprintf(f, "\"%s\",\"%s\",\"%s\",\"%s\",%d,%llu,%.4f,%.4f,%s,\"%s\",%.4f,%d,\"%s\"\n",
            o->label, inf_fmt_name(o->fmt), inf_fmt_cat(o->fmt), o->arch, o->bits,
            (unsigned long long)o->size, o->entropy, o->hi_entropy,
            o->packer ? o->packer_name : "", o->top, o->top_conf,
            vso_grade((sift_t *)o), o->sha256);
    return 0;
}

void vso_usage(FILE *f)
{
    fprintf(f,
            "sift %s - static artifact triage and CS domain classification\n"
            "usage: sift [options] <file...>\n"
            "  -j, --json      JSON output\n"
            "  -c, --csv       CSV output\n"
            "  -s, --strings   include sampled strings\n"
            "  -q, --quiet     suppress per-file text output\n"
            "  -h, --help      this text\n"
            "  -V, --version   version\n"
            "static analysis only, never executes or modifies input\n",
            VSO_TOOL_VER);
}
