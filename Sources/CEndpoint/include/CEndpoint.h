#pragma once
#include <stdint.h>
#include <stdbool.h>
typedef struct { uint64_t device; uint64_t inode; } aba_file;
typedef struct {
    uint64_t device, inode;
    int32_t pid;
    uint32_t pid_version, uid, code_flags;
    bool platform_binary;
    const char *executable, *signing_id, *team_id, *path;
} aba_event;
typedef bool (*aba_decide)(const aba_event *, void *);
typedef void (*aba_report)(const aba_event *, bool denied, int response_result, void *);
// Returns 0 on success; 100 + es_new_client_result on client failure.
int aba_start(const aba_file *, uint32_t count, aba_decide, aba_report, void *context);
void aba_stop(void);
