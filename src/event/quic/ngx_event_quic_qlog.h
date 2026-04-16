/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_QLOG_H_INCLUDED_
#define _NGX_EVENT_QUIC_QLOG_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic.h>
#include <ngx_event_quic_connection.h>


typedef enum {
    NGX_QUIC_QLOG_SIDE_LOCAL = 0,
    NGX_QUIC_QLOG_SIDE_REMOTE
} ngx_quic_qlog_side_e;


typedef enum {
    NGX_QUIC_QLOG_PKT_LOST_TIME = 0,
    NGX_QUIC_QLOG_PKT_LOST_REORDERING
} ngx_quic_qlog_pkt_lost_e;


typedef enum {
    NGX_QUIC_QLOG_CC_UNKNOWN = 0,
    NGX_QUIC_QLOG_CC_SLOW_START,
    NGX_QUIC_QLOG_CC_CONGESTION_AVOIDANCE,
    NGX_QUIC_QLOG_CC_RECOVERY
} ngx_quic_qlog_cc_state_e;


#if (NGX_QUIC_QLOG)


struct ngx_quic_qlog_s {
    ngx_fd_t                  fd;
    ngx_str_t                 path;

    u_char                   *buf;
    u_char                   *last;
    u_char                   *end;

    ngx_log_t                *log;

    ngx_msec_t                start_time;

    ngx_uint_t                importance;

    size_t                    bytes_written;
    size_t                    max_size;

    unsigned                  sent:1;
    unsigned                  closed:1;

    /* previous metrics for dedup */
    ngx_msec_t                prev_min_rtt;
    ngx_msec_t                prev_avg_rtt;
    ngx_msec_t                prev_latest_rtt;
    ngx_msec_t                prev_rttvar;
    ngx_uint_t                prev_pto_count;
    size_t                    prev_cwnd;
    size_t                    prev_in_flight;
    size_t                    prev_ssthresh;

    ngx_quic_qlog_cc_state_e  prev_cc_state;
};


#define ngx_qlog_write_literal(p, end, s)                                    \
    do {                                                                     \
        size_t n = ((p) < (end)) ? (size_t) ((end) - (p)) : 0;               \
        if (n > sizeof(s) - 1) {                                             \
            n = sizeof(s) - 1;                                               \
        }                                                                    \
        (p) = ngx_cpymem(p, s, n);                                           \
    } while (0)

#define ngx_qlog_write(p, end, fmt, ...)                                     \
    (p = ngx_slprintf(p, end, fmt, ##__VA_ARGS__))

#define ngx_qlog_write_char(p, end, c)                                       \
    do {                                                                     \
        if ((p) < (end)) {                                                   \
            *(p)++ = (c);                                                    \
        }                                                                    \
    } while (0)

#define ngx_qlog_write_pair(p, end, key, fmt, ...)                           \
    (p = ngx_slprintf(p, end, "\"%s\":" fmt, key, ##__VA_ARGS__))

#define ngx_qlog_write_pair_num(p, end, key, val)                            \
    ngx_qlog_write_pair(p, end, key, "%uL", (uint64_t)val)

#define ngx_qlog_write_pair_bool(p, end, key, val)                           \
    ngx_qlog_write_pair(p, end, key, "%s", (val) ? "true" : "false")

#define ngx_qlog_write_pair_str(p, end, key, val)                            \
    ngx_qlog_write_pair(p, end, key, "\"%s\"", val)

#define ngx_qlog_write_pair_strv(p, end, key, val)                           \
    ngx_qlog_write_pair(p, end, key, "\"%V\"", val)

#define ngx_qlog_write_pair_hex(p, end, key, val, len)                       \
    ngx_qlog_write_pair(p, end, key, "\"%*xs\"", (size_t) len, val)

#define ngx_qlog_write_pair_duration(p, end, key, val)                       \
    ngx_qlog_write_pair(p, end, key, "%M", val)


ngx_int_t ngx_quic_qlog_init(ngx_connection_t *c, ngx_quic_connection_t *qc);
void ngx_quic_qlog_close(ngx_quic_connection_t *qc);

void ngx_quic_qlog_connection_started(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_connection_closed(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_cid_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_client_id_t *old_cid,
    ngx_quic_client_id_t *new_cid);
void ngx_quic_qlog_mtu_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_path_t *path, size_t old_mtu);
void ngx_quic_qlog_version_information(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_alpn_information(ngx_connection_t *c,
    ngx_quic_connection_t *qc, u_char *alpn, unsigned int alpn_len);
void ngx_quic_qlog_transport_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_tp_t *params,
    ngx_quic_qlog_side_e side);
void ngx_quic_qlog_pkt_dropped(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt, const char *trigger);
void ngx_quic_qlog_stream_state_updated(ngx_connection_t *c,
    ngx_quic_stream_t *qs, ngx_uint_t is_send,
    ngx_uint_t old_state, ngx_uint_t new_state);
void ngx_quic_qlog_key_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_uint_t level, ngx_uint_t is_write);
void ngx_quic_qlog_key_discarded(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_uint_t level);
void ngx_quic_qlog_recovery_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_metrics_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_congestion_state_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_qlog_cc_state_e state);
void ngx_quic_qlog_loss_timer_updated(ngx_connection_t *c,
    ngx_quic_connection_t *qc, const char *event_type,
    const char *timer_type, ngx_msec_int_t delta);
void ngx_quic_qlog_pkt_lost(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_send_ctx_t *ctx, ngx_quic_frame_t *start,
    ngx_quic_qlog_pkt_lost_e trigger);

void ngx_quic_qlog_pkt_received_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_pkt_received_end(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_header_t *pkt);
void ngx_quic_qlog_pkt_sent_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void ngx_quic_qlog_pkt_sent_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
void ngx_quic_qlog_write_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *f);

ngx_quic_qlog_t *ngx_quic_qlog_start_event(ngx_quic_qlog_t *qlog,
    u_char **pp, u_char **pend, ngx_uint_t min_importance,
    const char *name);
ngx_int_t ngx_quic_qlog_write(ngx_quic_qlog_t *qlog, u_char *buf, size_t size);

#else /* NGX_QUIC_QLOG */

#define ngx_quic_qlog_init(c, qc)  NGX_OK
#define ngx_quic_qlog_close(qc)
#define ngx_quic_qlog_connection_started(c, qc)
#define ngx_quic_qlog_connection_closed(c, qc)
#define ngx_quic_qlog_cid_updated(c, qc, old_cid, new_cid)
#define ngx_quic_qlog_mtu_updated(c, qc, path, old_mtu)
#define ngx_quic_qlog_version_information(c, qc)
#define ngx_quic_qlog_alpn_information(c, qc, alpn, alpn_len)
#define ngx_quic_qlog_transport_parameters_set(c, qc, params, side)
#define ngx_quic_qlog_pkt_dropped(c, qc, pkt, trigger)
#define ngx_quic_qlog_stream_state_updated(c, qs, is_send, old_state, new_state)
#define ngx_quic_qlog_key_updated(c, qc, level, is_write)
#define ngx_quic_qlog_key_discarded(c, qc, level)
#define ngx_quic_qlog_recovery_parameters_set(c, qc)
#define ngx_quic_qlog_metrics_updated(c, qc)
#define ngx_quic_qlog_congestion_state_updated(c, qc, state)
#define ngx_quic_qlog_loss_timer_updated(c, qc, event_type, timer_type, delta)
#define ngx_quic_qlog_pkt_lost(c, qc, ctx, start, trigger)
#define ngx_quic_qlog_pkt_received_start(c, qc)
#define ngx_quic_qlog_pkt_received_end(c, qc, pkt)
#define ngx_quic_qlog_pkt_sent_start(c, qc)
#define ngx_quic_qlog_pkt_sent_end(c, qc, pkt)
#define ngx_quic_qlog_write_frame(qc, f)

#endif /* NGX_QUIC_QLOG */


#endif /* _NGX_EVENT_QUIC_QLOG_H_INCLUDED_ */
