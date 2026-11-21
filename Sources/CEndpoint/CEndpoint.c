#include "CEndpoint.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <string.h>
static es_client_t *client;
static aba_file *files;
static uint32_t file_count;
static char *copy_token(es_string_token_t token) { return strndup(token.data, token.length); }
int aba_start(const aba_file *input, uint32_t count, aba_decide decide, aba_report report, void *context) {
    if (client || !count) return -1;
    files = calloc(count, sizeof(*files));
    if (!files) return -2;
    memcpy(files, input, count * sizeof(*files)); file_count = count;
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
        const es_file_t *f = m->event.open.file;
        bool matched = false;
        if (m->event.open.fflag & FREAD) {
            for (uint32_t i = 0; i < file_count; ++i)
                if (files[i].device == (uint64_t)(uint32_t)f->stat.st_dev && files[i].inode == f->stat.st_ino) { matched = true; break; }
        }
        if (!matched) { es_respond_flags_result(c, m, UINT32_MAX, false); return; }
        const es_process_t *p = m->process;
        char *exe = copy_token(p->executable->path), *sid = copy_token(p->signing_id);
        char *team = copy_token(p->team_id), *path = copy_token(f->path);
        if (!exe || !sid || !team || !path) {
            es_respond_flags_result(c, m, UINT32_MAX, false);
            free(exe); free(sid); free(team); free(path); return;
        }
        aba_event event = { (uint64_t)(uint32_t)f->stat.st_dev, f->stat.st_ino,
            audit_token_to_pid(p->audit_token), audit_token_to_pidversion(p->audit_token),
            audit_token_to_euid(p->audit_token), p->codesigning_flags, p->is_platform_binary,
            exe, sid, team, path };
        bool deny = decide(&event, context);
        es_respond_result_t response = es_respond_flags_result(c, m, deny ? 0 : UINT32_MAX, false);
        report(&event, deny, (int)response, context);
        free(exe); free(sid); free(team); free(path);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) { free(files); files = NULL; client = NULL; return 100 + (int)result; }
    es_event_type_t event = ES_EVENT_TYPE_AUTH_OPEN;
    if (es_subscribe(client, &event, 1) != ES_RETURN_SUCCESS) { aba_stop(); return -3; }
    return 0;
}
void aba_stop(void) {
    if (client) { es_unsubscribe_all(client); es_delete_client(client); client = NULL; }
    free(files); files = NULL; file_count = 0;
}
