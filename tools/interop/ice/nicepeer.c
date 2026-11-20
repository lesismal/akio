/* A libnice peer for only-ice's interop test (crates/only-ice/tests/libnice.rs): one stream
 * of two components (RTP and RTCP without rtcp-mux) on 127.0.0.1, driven by lines on stdin
 * and reporting on stdout.
 *
 *   nicepeer [-controlling] [-regular] [-lite]
 *
 * Out: CRED <ufrag> <pwd>, CAND <a=candidate line> (one per local candidate of each
 *      component), GATHERED, STATE <component> <state>, SELECTED <component> <local port>
 *      <remote port>, RECV <component> <data>, ERR <text>.
 * In:  CRED <ufrag> <pwd>, CAND <candidate line>, GO (sets the remote candidates), QUIT.
 *
 * Once a component is ready it sends "hello-<component>" on it, and it echoes what it receives
 * as "echo:<data>" on the same component (what arrives earlier is echoed once it is ready).
 */
#include <nice/agent.h>
#include <stdio.h>
#include <string.h>

static GMainLoop *loop;
static NiceAgent *agent;
static guint stream;
static GSList *remote[3];
static gboolean said_hello[3];
/* Echoes of data that arrived before the component was ready (libnice sends nothing before). */
static GSList *pending[3];

static void on_gathered(NiceAgent *a, guint s, gpointer d) {
    gchar *ufrag = NULL, *pwd = NULL;
    (void)d;
    nice_agent_get_local_credentials(a, s, &ufrag, &pwd);
    printf("CRED %s %s\n", ufrag, pwd);
    g_free(ufrag);
    g_free(pwd);
    for (guint c = 1; c <= 2; c++) {
        GSList *cands = nice_agent_get_local_candidates(a, s, c);
        for (GSList *i = cands; i; i = i->next) {
            gchar *sdp = nice_agent_generate_local_candidate_sdp(a, i->data);
            printf("CAND %s\n", sdp);
            g_free(sdp);
        }
        g_slist_free_full(cands, (GDestroyNotify)nice_candidate_free);
    }
    printf("GATHERED\n");
    fflush(stdout);
}

static void on_state(NiceAgent *a, guint s, guint c, guint state, gpointer d) {
    (void)d;
    printf("STATE %u %s\n", c, nice_component_state_to_string(state));
    if (state == NICE_COMPONENT_STATE_READY && c <= 2 && !said_hello[c]) {
        gchar *hello = g_strdup_printf("hello-%u", c);
        said_hello[c] = TRUE;
        if (nice_agent_send(a, s, c, strlen(hello), hello) < 0)
            printf("ERR send hello on %u\n", c);
        g_free(hello);
        for (GSList *i = pending[c]; i; i = i->next)
            nice_agent_send(a, s, c, strlen(i->data), i->data);
        g_slist_free_full(pending[c], g_free);
        pending[c] = NULL;
    }
    fflush(stdout);
}

static void on_selected(NiceAgent *a, guint s, guint c, NiceCandidate *l, NiceCandidate *r,
                        gpointer d) {
    (void)a;
    (void)s;
    (void)d;
    printf("SELECTED %u %u %u\n", c, nice_address_get_port(&l->base_addr),
           nice_address_get_port(&r->addr));
    fflush(stdout);
}

static void on_recv(NiceAgent *a, guint s, guint c, guint len, gchar *buf, gpointer d) {
    (void)d;
    gchar *data = g_strndup(buf, len);
    printf("RECV %u %s\n", c, data);
    fflush(stdout);
    if (!g_str_has_prefix(data, "echo:")) {
        gchar *echo = g_strdup_printf("echo:%s", data);
        if (c <= 2 && !said_hello[c])
            pending[c] = g_slist_append(pending[c], echo);
        else {
            nice_agent_send(a, s, c, strlen(echo), echo);
            g_free(echo);
        }
    }
    g_free(data);
}

static gboolean on_stdin(GIOChannel *ch, GIOCondition cond, gpointer d) {
    gchar *line = NULL;
    gsize len = 0;
    (void)cond;
    (void)d;
    GIOStatus st = g_io_channel_read_line(ch, &line, &len, NULL, NULL);
    if (st == G_IO_STATUS_EOF || st == G_IO_STATUS_ERROR) {
        g_main_loop_quit(loop);
        return FALSE;
    }
    if (!line)
        return TRUE;
    g_strchomp(line);
    if (g_str_has_prefix(line, "CRED ")) {
        gchar **f = g_strsplit(line + 5, " ", 2);
        if (f[0] && f[1])
            nice_agent_set_remote_credentials(agent, stream, f[0], f[1]);
        g_strfreev(f);
    } else if (g_str_has_prefix(line, "CAND ")) {
        const gchar *c = line + 5;
        gchar *sdp = g_str_has_prefix(c, "a=") ? g_strdup(c) : g_strdup_printf("a=%s", c);
        NiceCandidate *cand = nice_agent_parse_remote_candidate_sdp(agent, stream, sdp);
        if (!cand || cand->component_id < 1 || cand->component_id > 2)
            printf("ERR bad candidate %s\n", sdp);
        else
            remote[cand->component_id] = g_slist_append(remote[cand->component_id], cand);
        g_free(sdp);
    } else if (strcmp(line, "GO") == 0) {
        for (guint c = 1; c <= 2; c++)
            if (nice_agent_set_remote_candidates(agent, stream, c, remote[c]) < 1)
                printf("ERR no remote candidates for %u\n", c);
    } else if (strcmp(line, "QUIT") == 0) {
        g_main_loop_quit(loop);
    }
    fflush(stdout);
    g_free(line);
    return TRUE;
}

int main(int argc, char **argv) {
    gboolean controlling = FALSE;
    NiceAgentOption opts = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-controlling") == 0)
            controlling = TRUE;
        else if (strcmp(argv[i], "-regular") == 0)
            opts |= NICE_AGENT_OPTION_REGULAR_NOMINATION;
        else if (strcmp(argv[i], "-lite") == 0)
            opts |= NICE_AGENT_OPTION_LITE_MODE;
    }
    loop = g_main_loop_new(NULL, FALSE);
    agent = nice_agent_new_full(g_main_loop_get_context(loop), NICE_COMPATIBILITY_RFC5245, opts);
    g_object_set(agent, "controlling-mode", controlling, "ice-tcp", FALSE, NULL);
    NiceAddress lo;
    nice_address_init(&lo);
    nice_address_set_from_string(&lo, "127.0.0.1");
    nice_agent_add_local_address(agent, &lo);
    g_signal_connect(agent, "candidate-gathering-done", G_CALLBACK(on_gathered), NULL);
    g_signal_connect(agent, "component-state-changed", G_CALLBACK(on_state), NULL);
    g_signal_connect(agent, "new-selected-pair-full", G_CALLBACK(on_selected), NULL);
    stream = nice_agent_add_stream(agent, 2);
    for (guint c = 1; c <= 2; c++)
        nice_agent_attach_recv(agent, stream, c, g_main_loop_get_context(loop), on_recv, NULL);
    GIOChannel *in = g_io_channel_unix_new(0);
    g_io_add_watch(in, G_IO_IN | G_IO_HUP, on_stdin, NULL);
    if (!nice_agent_gather_candidates(agent, stream)) {
        printf("ERR gathering\n");
        return 1;
    }
    g_main_loop_run(loop);
    g_io_channel_unref(in);
    g_object_unref(agent);
    g_main_loop_unref(loop);
    return 0;
}
