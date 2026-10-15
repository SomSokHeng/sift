#include "sift.h"

int inf_dom_name(int id);

static int vso_analyze(const char *path, sift_t *o, int want_strings)
{
    unsigned char *b = NULL;
    size_t n = 0;
    if (vso_read_file(path, &b, &n) != 0) {
        fprintf(stderr, "sift: cannot read %s\n", path);
        return -1;
    }
    if (n < 8) {
        fprintf(stderr, "sift: %s too small to triage\n", path);
        free(b);
        return -1;
    }

    memset(o, 0, sizeof(*o));
    snprintf(o->label, sizeof(o->label), "%s", path);
    o->size = n;
    o->entropy = inf_entropy(b, n);
    inf_hi_entropy(b, n, &o->hi_entropy);
    vso_hash(b, n, o->sha256, o->sha1, o->md5);

    int bits = 0, le = 1, is_dyn = 0;
    uint32_t fmt = FMT_NONE;
    vso_detect_fmt(b, n, &fmt, &bits, &le, &is_dyn);
    o->fmt = fmt;
    o->bits = bits;
    o->is_le = le;
    o->is_dyn = is_dyn;

    if (fmt == FMT_ELF || fmt == FMT_ELF_CORE)
        vso_elf_parse(b, n, o);
    else if (fmt == FMT_PE || fmt == FMT_COFF)
        vso_pe_parse(b, n, o);

    if (!vso_is_self(b, n)) {
        vso_scan_consts(b, n, o);
        vso_scan_libs(b, n, o);
    }
    if (want_strings)
        vso_scan_strings(b, n, o);
    inf_classify(o);
    free(b);
    return 0;
}

int main(int argc, char **argv)
{
    int as_json = 0, as_csv = 0, want_strings = 0, quiet = 0;
    const char *files[512];
    int nf = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            vso_usage(stdout);
            return 0;
        }
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("sift %s\n", VSO_TOOL_VER);
            return 0;
        }
        if (!strcmp(a, "-j") || !strcmp(a, "--json"))
            as_json = 1;
        else if (!strcmp(a, "-c") || !strcmp(a, "--csv"))
            as_csv = 1;
        else if (!strcmp(a, "-s") || !strcmp(a, "--strings"))
            want_strings = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet"))
            quiet = 1;
        else if (a[0] == '-' && a[1]) {
            fprintf(stderr, "sift: unknown option %s\n", a);
            return 2;
        } else if (nf < 512) {
            files[nf++] = a;
        }
    }

    if (!nf) {
        vso_usage(stderr);
        return 2;
    }

    int bad = 0;
    if (as_csv) {
        sift_t o;
        for (int i = 0; i < nf; i++) {
            if (vso_analyze(files[i], &o, want_strings) != 0) {
                bad++;
                continue;
            }
            vso_csv(&o, stdout);
        }
        return bad ? 1 : 0;
    }
    if (as_json) {
        sift_t o;
        printf("[");
        for (int i = 0; i < nf; i++) {
            if (vso_analyze(files[i], &o, want_strings) != 0) {
                bad++;
                continue;
            }
            printf("%s", i ? "," : "");
            vso_json(&o, stdout);
        }
        printf("]\n");
        return bad ? 1 : 0;
    }

    for (int i = 0; i < nf; i++) {
        sift_t o;
        if (vso_analyze(files[i], &o, want_strings) != 0) {
            bad++;
            continue;
        }
        if (!quiet) {
            vso_print(&o, stdout);
            if (want_strings && o.nstrs) {
                printf("strings\n");
                for (int k = 0; k < o.nstrs; k++)
                    printf("  %s\n", o.strs[k]);
            }
            printf("\n");
        }
    }
    return bad ? 1 : 0;
}
