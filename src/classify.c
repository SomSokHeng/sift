#include "sift.h"

static const char *CATS[17] = {
    "unknown", "systems", "crypto", "network", "web", "database",
    "ml-ai", "media", "toolchain", "game", "reverse", "embedded",
    "security", "science", "finance", "mobile", "other"
};

const char *inf_dom_name(int id)
{
    if (id < 0 || id > 16)
        return "unknown";
    return CATS[id];
}

static const struct {
    const char *needle;
    int dom;
} SIGS[] = {
    {"libcrypto", 2}, {"libssl", 2}, {"openssl", 2}, {"EVP_", 2}, {"SSL_", 2},
    {"mbedtls", 2}, {"libsodium", 2}, {"boringssl", 2}, {"AES_encrypt", 2},
    {"SHA256_", 2}, {"RSA_", 2}, {"ECDSA_", 2}, {"secp256k1", 2},
    {"curve25519", 2}, {"x25519", 2}, {"ed25519", 2}, {"chacha20", 2},
    {"poly1305", 2}, {"hmac", 2}, {"argon2", 2}, {"bcrypt", 2}, {"pbkdf2", 2},
    {"RSA_PKCS", 2}, {"DIGITAL", 2}, {"ENCRYPTED", 2},

    {"socket", 3}, {"connect", 3}, {"bind", 3}, {"listen", 3}, {"accept", 3},
    {"getaddrinfo", 3}, {"gethostbyname", 3}, {"sendto", 3}, {"recvfrom", 3},
    {"AF_INET", 3}, {"SOCK_STREAM", 3}, {"netdb.h", 3}, {"inet_ntop", 3},
    {"tcpdump", 3}, {"libcurl", 3}, {"winsock", 3}, {"ws2_32", 3}, {"epoll", 3},

    {"<html", 4}, {"HTTP/1.", 4}, {"https://", 4}, {"<!DOCTYPE", 4}, {"</div>", 4},
    {"text/html", 4}, {"application/json", 4}, {"nginx", 4}, {"apache", 4},
    {"express", 4}, {"flask", 4}, {"django", 4}, {"Content-Type", 4},

    {"sqlite3", 5}, {"SELECT ", 5}, {"INSERT INTO", 5}, {"CREATE TABLE", 5},
    {"postgres", 5}, {"mysql", 5}, {"mongodb", 5}, {"redis", 5}, {"B-tree", 5},
    {"PRAGMA", 5}, {"sqlite_master", 5},

    {"tensorflow", 6}, {"torch", 6}, {"numpy", 6}, {"scipy", 6}, {"sklearn", 6},
    {"pytorch", 6}, {"conv2d", 6}, {"backward", 6}, {"gradient", 6},
    {"softmax", 6}, {"tensor", 6}, {"neural", 6}, {"keras", 6}, {"cuda", 6},
    {"GGML", 6}, {"gguf", 6}, {"safetensors", 6}, {"autograd", 6},

    {"mp3", 7}, {"ID3", 7}, {"jpeg", 7}, {"png", 7}, {"ffmpeg", 7},
    {"avcodec", 7}, {"libvpx", 7}, {"opus", 7}, {"flac", 7}, {"yuv", 7},

    {"gcc", 8}, {"clang", 8}, {"llvm", 8}, {"ld-linux", 8}, {"libstdc++", 8},
    {"rustc", 8}, {"cargo", 8}, {"cmake", 8}, {"objcopy", 8}, {"glibc", 8},
    {"GNU C", 8}, {"mingw", 8}, {"msvc", 8}, {"debug_info", 8},

    {"unity", 9}, {"unreal", 9}, {"godot", 9}, {"sdl2", 9}, {"vulkan", 9},
    {"opengl", 9}, {"directx", 9}, {"d3d11", 9}, {"gameplay", 9},

    {"radare2", 10}, {"r2_", 10}, {"ghidra", 10}, {"ida", 10}, {"objdump", 10},
    {"disassembly", 10}, {"symbols", 10}, {"elf.h", 10}, {"disasm", 10},
    {"capstone", 10}, {"keystone", 10}, {"unicorn", 10},

    {"stm32", 11}, {"nrf52", 11}, {"esp8266", 11}, {"arduino", 11},
    {"cortex", 11}, {"firmware", 11}, {"bootloader", 11}, {"rtos", 11},

    {"selinux", 12}, {"apparmor", 12}, {"sandbox", 12}, {"seccomp", 12},
    {"gpg", 12}, {"pgp", 12}, {"signature", 12}, {"verify", 12}, {"certificate", 12},

    {"numpy.linalg", 13}, {"scipy.integrate", 13}, {"qutip", 13}, {"units", 13},
    {"simulation", 13}, {"newton", 13}, {"molecule", 13}, {"genome", 13},

    {"decimal", 14}, {"bn_mul", 14}, {"big_number", 14}, {"exchange", 14},
    {"ticker", 14}, {"portfolio", 14}, {"interest_rate", 14}, {"ledger", 14},

    {"Objective-C", 15}, {"UIKit", 15}, {"android", 15}, {"dalvik", 15},
    {"apk", 15}, {"ios", 15}, {"swift", 15}, {"kotlin", 15}
};

int inf_classify(sift_t *o)
{
    int sc[17];
    memset(sc, 0, sizeof(sc));

    for (int i = 0; i < o->nstrs; i++) {
        const char *s = o->strs[i];
        for (size_t k = 0; k < sizeof(SIGS) / sizeof(SIGS[0]); k++) {
            const char *nd = SIGS[k].needle;
            size_t nl = strlen(nd);
            if (strstr(s, nd)) {
                sc[SIGS[k].dom] += 2;
                break;
            }
            (void)nl;
        }
    }
    for (int i = 0; i < o->nlibs; i++) {
        const char *s = o->libs[i];
        for (size_t k = 0; k < sizeof(SIGS) / sizeof(SIGS[0]); k++) {
            if (strstr(s, SIGS[k].needle)) {
                sc[SIGS[k].dom] += 3;
                break;
            }
        }
    }
    for (int i = 0; i < o->nconsts; i++) {
        if (strstr(o->consts[i], "AES"))
            sc[2] += 4;
        if (strstr(o->consts[i], "SHA-256"))
            sc[2] += 4;
        if (strstr(o->consts[i], "MD5"))
            sc[2] += 3;
    }

    const char *c = inf_fmt_cat(o->fmt);
    if (c) {
        for (int d = 1; d <= 16; d++)
            if (!strcmp(c, CATS[d]))
                sc[d] += 5;
    }

    if (o->packer)
        sc[12] += 6;
    if (o->hi_entropy > 7.5)
        sc[2] += 1;
    if (o->stripped)
        sc[12] += 1;

    o->ndom = 0;
    for (int d = 1; d <= 16; d++) {
        if (sc[d] > 0) {
            o->dom[o->ndom++] = sc[d];
        }
    }
    o->top[0] = 0;
    o->top_conf = 0;
    int best = 0, bi = 0;
    for (int d = 1; d <= 16; d++)
        if (sc[d] > best) {
            best = sc[d];
            bi = d;
        }
    if (best > 0) {
        snprintf(o->top, sizeof(o->top), "%s", CATS[bi]);
        int tot = 0;
        for (int d = 1; d <= 16; d++)
            tot += sc[d];
        o->top_conf = tot ? (double)best / (double)tot : 0.0;
    } else {
        snprintf(o->top, sizeof(o->top), "unknown");
        o->top_conf = 0.0;
    }
    return 0;
}

int vso_grade(sift_t *o)
{
    int s = 100;
    if (o->is_signed)
        s += 0;
    if (o->has_nx)
        s += 0;
    else
        s -= 25;
    if (!o->has_pie)
        s -= 20;
    if (!o->has_canary)
        s -= 15;
    if (!o->has_relro)
        s -= 10;
    if (o->packer)
        s -= 20;
    if (o->hi_entropy > 7.5)
        s -= 15;
    if (o->stripped)
        s -= 5;
    if (s > 100)
        s = 100;
    return s;
}
