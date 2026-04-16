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

typedef struct ngx_quic_qlog_s  ngx_quic_qlog_t;


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
