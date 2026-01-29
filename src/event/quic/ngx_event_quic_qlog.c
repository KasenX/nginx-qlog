#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic.h>
#include <ngx_event_quic_qlog.h>


#define NGX_QUIC_QLOG_BUF_SIZE  4096


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
    if ((p) < (end))                                                         \
        *(p)++ = (c)

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


struct ngx_quic_qlog_s {
    ngx_fd_t   fd;
    ngx_str_t  path;

    u_char    *buf;
    u_char    *last;
    u_char    *end;

    ngx_msec_t start_time;

    size_t     bytes_written;
    size_t     max_size;

    unsigned   closed:1;
};


static ngx_inline uint64_t ngx_quic_qlog_now(ngx_quic_qlog_t *qlog);
static ngx_int_t ngx_quic_qlog_open(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
static void ngx_quic_qlog_write_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_uint_t sent);
static void ngx_quic_qlog_write_end(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_header_t *pkt, uint64_t pkt_number);
static ngx_int_t ngx_quic_qlog_write_buf(ngx_connection_t *c,
    ngx_quic_qlog_t *qlog, u_char *buf, size_t size);
static ngx_int_t ngx_quic_qlog_write_header(ngx_connection_t *c,
    ngx_quic_connection_t *qc, uint64_t reference_time_ms);
static const char *ngx_quic_qlog_packet_name(uint8_t flags);
static const char *ngx_quic_qlog_packet_name_by_level(ngx_uint_t level);
static u_char *ngx_quic_qlog_padding_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_ping_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_ack_frame(u_char *p, u_char *end,
    ngx_connection_t *c, ngx_quic_connection_t *qc, ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_reset_stream_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_stop_sending_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_crypto_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_new_token_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_stream_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_max_data_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_max_stream_data_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_max_streams_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_data_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_stream_data_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_streams_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_new_connection_id_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_retire_connection_id_frame(u_char *p,
    u_char *end, ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_path_challenge_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_path_response_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_connection_close_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);
static u_char *ngx_quic_qlog_handshake_done_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f);


ngx_int_t
ngx_quic_qlog_init(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    uint64_t     reference_time_ms;
    ngx_time_t  *tp;

    if (!qc->conf->qlog_enabled) {
        return NGX_DECLINED;
    }

    if (qc->conf->qlog_allow) {
        if (ngx_cidr_match(c->sockaddr, qc->conf->qlog_allow) != NGX_OK) {
            return NGX_DECLINED;
        }
    }

    if (qc->conf->qlog_sample_n > 1) {
        if ((ngx_uint_t) ngx_random() % qc->conf->qlog_sample_n != 0) {
            return NGX_DECLINED;
        }
    }

    qc->qlog = ngx_pcalloc(c->pool, sizeof(ngx_quic_qlog_t));
    if (qc->qlog == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_qlog_open(c, qc) != NGX_OK) {
        qc->qlog->closed = 1;
        return NGX_ERROR;
    }

    tp = ngx_timeofday();
    reference_time_ms = (uint64_t) tp->sec * 1000 + tp->msec;
    qc->qlog->start_time = ngx_current_msec;

    if (ngx_quic_qlog_write_header(c, qc, reference_time_ms) != NGX_OK) {
        ngx_close_file(qc->qlog->fd);
        qc->qlog->fd = NGX_INVALID_FILE;
        qc->qlog->closed = 1;
        return NGX_ERROR;
    }

    qc->qlog->buf = ngx_palloc(c->pool, NGX_QUIC_QLOG_BUF_SIZE);
    if (qc->qlog->buf == NULL) {
        ngx_close_file(qc->qlog->fd);
        qc->qlog->fd = NGX_INVALID_FILE;
        qc->qlog->closed = 1;
        return NGX_ERROR;
    }

    qc->qlog->end = qc->qlog->buf + NGX_QUIC_QLOG_BUF_SIZE;
    qc->qlog->last = qc->qlog->buf;

    qc->qlog->bytes_written = 0;
    qc->qlog->max_size = qc->conf->qlog_max_size;
    qc->qlog->closed = 0;

    return NGX_OK;
}


void
ngx_quic_qlog_close(ngx_quic_connection_t *qc)
{
    if (qc->qlog && qc->qlog->fd != NGX_INVALID_FILE) {
        ngx_close_file(qc->qlog->fd);
        qc->qlog->fd = NGX_INVALID_FILE;
        qc->qlog->closed = 1;
    }
}


void
ngx_quic_qlog_transport_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_tp_t *params, ngx_quic_qlog_side_e side)
{
    u_char           *p, *end;
    uint64_t          timestamp;
    ngx_quic_qlog_t  *qlog;
    u_char            buf[2048];

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    p = buf;
    end = buf + sizeof(buf);

    timestamp = ngx_quic_qlog_now(qlog);

    ngx_qlog_write(p, end, "\x1e{\"time\":%uL,\"name\":"
                   "\"transport:parameters_set\",\"data\":{\"owner\":\"%s\",",
                   timestamp,
                   side == NGX_QUIC_QLOG_SIDE_LOCAL ? "local" : "remote");
    ngx_qlog_write_pair_hex(p, end, "initial_source_connection_id",
                            params->initial_scid.data,
                            params->initial_scid.len);
    ngx_qlog_write_char(p, end, ',');
    if (side == NGX_QUIC_QLOG_SIDE_LOCAL) {
        ngx_qlog_write_pair_hex(p, end, "original_destination_connection_id",
                                params->original_dcid.data,
                                params->original_dcid.len);
        ngx_qlog_write_char(p, end, ',');
    }
    if (params->retry_scid.len) {
        ngx_qlog_write_pair_hex(p, end, "retry_source_connection_id",
                                params->retry_scid.data,
                                params->retry_scid.len);
        ngx_qlog_write_char(p, end, ',');
    }
    ngx_qlog_write_pair_hex(p, end, "stateless_reset_token",
                            params->sr_token, NGX_QUIC_SR_TOKEN_LEN);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_bool(p, end, "disable_active_migration",
                             params->disable_active_migration);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_duration(p, end, "max_idle_timeout",
                                 params->max_idle_timeout);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "max_udp_payload_size",
                            params->max_udp_payload_size);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "ack_delay_exponent",
                            params->ack_delay_exponent);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_duration(p, end, "max_ack_delay",
                                 params->max_ack_delay);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "active_connection_id_limit",
                            params->active_connection_id_limit);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_data",
                            params->initial_max_data);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_stream_data_bidi_local",
                            params->initial_max_stream_data_bidi_local);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_stream_data_bidi_remote",
                            params->initial_max_stream_data_bidi_remote);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_stream_data_uni",
                            params->initial_max_stream_data_uni);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_streams_bidi",
                            params->initial_max_streams_bidi);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_max_streams_uni",
                            params->initial_max_streams_uni);
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write_buf(c, qlog, buf, p - buf);
}


void
ngx_quic_qlog_recovery_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc)
{
    u_char           *p, *end;
    uint64_t          timestamp;
    ngx_quic_qlog_t  *qlog;
    size_t            max_datagram_size;
    uint64_t          min_cwnd;
    u_char            buf[512];

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    max_datagram_size = qc->path ? qc->path->mtu : qc->congestion.mtu;
    min_cwnd = 2 * (uint64_t) max_datagram_size;

    p = buf;
    end = buf + sizeof(buf);

    timestamp = ngx_quic_qlog_now(qlog);

    ngx_qlog_write(p, end, "\x1e{\"time\":%uL,\"name\":"
                   "\"recovery:parameters_set\",\"data\":{", timestamp);
    ngx_qlog_write_pair_num(p, end, "reordering_threshold", NGX_QUIC_PKT_THR);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair(p, end, "time_threshold", "%.3f", 1.125);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "timer_granularity",
                            NGX_QUIC_TIME_GRANULARITY);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_rtt", NGX_QUIC_INITIAL_RTT);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "max_datagram_size", max_datagram_size);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "initial_congestion_window",
                            qc->congestion.window);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "minimum_congestion_window", min_cwnd);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair(p, end, "loss_reduction_factor", "%.3f",
                        (double) NGX_QUIC_CUBIC_BETA / 10.0);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "persistent_congestion_threshold",
                            NGX_QUIC_PERSISTENT_CONGESTION_THR);
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write_buf(c, qlog, buf, p - buf);
}


void
ngx_quic_qlog_metrics_updated(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    u_char           *p, *end;
    uint64_t          timestamp;
    ngx_quic_qlog_t  *qlog;
    u_char            buf[512];

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    p = buf;
    end = buf + sizeof(buf);

    timestamp = ngx_quic_qlog_now(qlog);

    ngx_qlog_write(p, end, "\x1e{\"time\":%uL,\"name\":"
                   "\"recovery:metrics_updated\",\"data\":{", timestamp);

    if (qc->min_rtt != NGX_TIMER_INFINITE) {
        ngx_qlog_write_pair_duration(p, end, "min_rtt", qc->min_rtt);
        ngx_qlog_write_char(p, end, ',');
    }

    ngx_qlog_write_pair_duration(p, end, "smoothed_rtt", qc->avg_rtt);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_duration(p, end, "latest_rtt", qc->latest_rtt);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_duration(p, end, "rtt_variance", qc->rttvar);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "pto_count", qc->pto_count);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "congestion_window",
                            qc->congestion.window);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "bytes_in_flight",
                            qc->congestion.in_flight);

    if (qc->congestion.ssthresh != (size_t) -1) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ssthresh",
                                qc->congestion.ssthresh);
    }

    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write_buf(c, qlog, buf, p - buf);
}


void
ngx_quic_qlog_pkt_lost(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_send_ctx_t *ctx, ngx_quic_frame_t *start,
    ngx_quic_qlog_pkt_lost_e trigger)
{
    u_char           *p, *end;
    uint64_t          timestamp;
    ngx_quic_qlog_t  *qlog;
    u_char            buf[256];

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    p = buf;
    end = buf + sizeof(buf);

    timestamp = ngx_quic_qlog_now(qlog);

    ngx_qlog_write(p, end, "\x1e{\"time\":%uL,\"name\":"
                   "\"recovery:packet_lost\",\"data\":{\"header\":{",
                   timestamp);
    ngx_qlog_write_pair_str(p, end, "packet_type",
                            ngx_quic_qlog_packet_name_by_level(ctx->level));
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "packet_number", start->pnum);
    ngx_qlog_write_char(p, end, '}');
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "trigger",
                            trigger == NGX_QUIC_QLOG_PKT_LOST_TIME
                            ? "time_threshold"
                            : "reordering_threshold");
    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write_buf(c, qlog, buf, p - buf);
}


void
ngx_quic_qlog_pkt_dropped(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt, const char *trigger)
{
    u_char           *p, *end;
    uint64_t          timestamp;
    ngx_quic_qlog_t  *qlog;
    u_char            buf[256];

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    p = buf;
    end = buf + sizeof(buf);

    timestamp = ngx_quic_qlog_now(qlog);

    ngx_qlog_write(p, end, "\x1e{\"time\":%uL,\"name\":"
                   "\"transport:packet_dropped\",\"data\":{",
                   timestamp);

    ngx_qlog_write_literal(p, end, "\"header\":{");
    ngx_qlog_write_pair_str(p, end, "packet_type",
                            ngx_quic_qlog_packet_name(pkt->flags));

    if (pkt->decrypted) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "packet_number", pkt->pn);
    }

    ngx_qlog_write_char(p, end, '}');
    ngx_qlog_write_char(p, end, ',');

    ngx_qlog_write(p, end, "\"raw\":{\"length\":%uz}", pkt->len);

    if (trigger) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_str(p, end, "trigger", trigger);
    }

    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write_buf(c, qlog, buf, p - buf);
}


void
ngx_quic_qlog_pkt_received_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc)
{
    ngx_quic_qlog_write_start(c, qc, 0);
}


void
ngx_quic_qlog_pkt_received_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt)
{
    ngx_quic_qlog_write_end(c, qc, pkt, pkt->pn);
}


void
ngx_quic_qlog_pkt_sent_start(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_quic_qlog_write_start(c, qc, 1);
}


void
ngx_quic_qlog_pkt_sent_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt)
{
    ngx_quic_qlog_write_end(c, qc, pkt, pkt->number);
}


void
ngx_quic_qlog_write_frame(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_frame_t *f)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    p = qlog->last;
    end = qlog->end;

    switch (f->type) {
    case NGX_QUIC_FT_PADDING:
        p = ngx_quic_qlog_padding_frame(p, end, f);
        break;
    case NGX_QUIC_FT_PING:
        p = ngx_quic_qlog_ping_frame(p, end, f);
        break;
    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:
        p = ngx_quic_qlog_ack_frame(p, end, c, qc, f);
        break;
    case NGX_QUIC_FT_RESET_STREAM:
        p = ngx_quic_qlog_reset_stream_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STOP_SENDING:
        p = ngx_quic_qlog_stop_sending_frame(p, end, f);
        break;
    case NGX_QUIC_FT_CRYPTO:
        p = ngx_quic_qlog_crypto_frame(p, end, f);
        break;
    case NGX_QUIC_FT_NEW_TOKEN:
        p = ngx_quic_qlog_new_token_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STREAM:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:
        p = ngx_quic_qlog_stream_frame(p, end, f);
        break;
    case NGX_QUIC_FT_MAX_DATA:
        p = ngx_quic_qlog_max_data_frame(p, end, f);
        break;
    case NGX_QUIC_FT_MAX_STREAM_DATA:
        p = ngx_quic_qlog_max_stream_data_frame(p, end, f);
        break;
    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:
        p = ngx_quic_qlog_max_streams_frame(p, end, f);
        break;
    case NGX_QUIC_FT_DATA_BLOCKED:
        p = ngx_quic_qlog_data_blocked_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:
        p = ngx_quic_qlog_stream_data_blocked_frame(p, end, f);
        break;
    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:
        p = ngx_quic_qlog_streams_blocked_frame(p, end, f);
        break;
    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        p = ngx_quic_qlog_new_connection_id_frame(p, end, f);
        break;
    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        p = ngx_quic_qlog_retire_connection_id_frame(p, end, f);
        break;
    case NGX_QUIC_FT_PATH_CHALLENGE:
        p = ngx_quic_qlog_path_challenge_frame(p, end, f);
        break;
    case NGX_QUIC_FT_PATH_RESPONSE:
        p = ngx_quic_qlog_path_response_frame(p, end, f);
        break;
    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        p = ngx_quic_qlog_connection_close_frame(p, end, f);
        break;
    case NGX_QUIC_FT_HANDSHAKE_DONE:
        p = ngx_quic_qlog_handshake_done_frame(p, end, f);
        break;

    default:
        ngx_qlog_write_literal(p, end, "{\"frame_type\":\"unknown\"}");
    }

    ngx_qlog_write_char(p, end, ',');

    qlog->last = p;
}


static void
ngx_quic_qlog_write_start(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_uint_t sent)
{
    uint64_t          timestamp;
    ngx_quic_qlog_t  *qlog;

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    qlog->last = qlog->buf;

    timestamp = ngx_quic_qlog_now(qlog);

    ngx_qlog_write(qlog->last, qlog->end,
                   "\x1e{\"time\":%uL,\"name\":\"transport:packet_%s\","
                   "\"data\":{\"frames\":[",
                   timestamp,
                   sent ? "sent" : "received");
}


static void
ngx_quic_qlog_write_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt, uint64_t pkt_number)
{
    size_t            size;
    ngx_quic_qlog_t  *qlog;

    qlog = qc->qlog;

    if (qlog == NULL || qlog->closed) {
        return;
    }

    if (qlog->last > qlog->buf && *(qlog->last - 1) == ',') {
        qlog->last--;
    }

    ngx_qlog_write(qlog->last, qlog->end,
                   "],\"header\":{\"packet_type\":\"%s\","
                   "\"packet_number\":%uL},"
                   "\"raw\":{\"length\":%uz}}}\n",
                   ngx_quic_qlog_packet_name(pkt->flags),
                   pkt_number,
                   pkt->len);

    size = qlog->last - qlog->buf;

    ngx_quic_qlog_write_buf(c, qlog, qlog->buf, size);
}


static ngx_int_t
ngx_quic_qlog_write_buf(ngx_connection_t *c, ngx_quic_qlog_t *qlog,
    u_char *buf, size_t size)
{
    ssize_t  n;

    n = ngx_write_fd(qlog->fd, buf, size);

    if (n == -1) {
        ngx_log_error(NGX_LOG_WARN, c->log, ngx_errno,
                      ngx_write_fd_n " to \"%V\" failed", &qlog->path);
        ngx_close_file(qlog->fd);
        qlog->fd = NGX_INVALID_FILE;
        qlog->closed = 1;
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      ngx_write_fd_n " to \"%V\" was incomplete: %z of %uz",
                      &qlog->path, n, size);
    }

    qlog->bytes_written += n;

    /* check whether writing the next event would exceed max_size */

    if (qlog->max_size
        && qlog->bytes_written + NGX_QUIC_QLOG_BUF_SIZE >= qlog->max_size)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "qlog max_size reached, closing \"%V\"", &qlog->path);
        ngx_close_file(qlog->fd);
        qlog->fd = NGX_INVALID_FILE;
        qlog->closed = 1;
    }

    return NGX_OK;
}


static ngx_inline uint64_t
ngx_quic_qlog_now(ngx_quic_qlog_t *qlog)
{
    return (uint64_t) (ngx_current_msec - qlog->start_time);
}


static ngx_int_t
ngx_quic_qlog_open(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    u_char     *p;
    ngx_str_t  *dir;
    ngx_str_t   file;

    dir = &qc->conf->qlog_path;

    if (dir->len == 0) {
        return NGX_ERROR;
    }

    file.len = dir->len + qc->path->cid->len * 2 + sizeof(".sqlog") - 1;
    file.data = ngx_pnalloc(c->pool, file.len + 1);
    if (file.data == NULL) {
        return NGX_ERROR;
    }

    p = file.data;

    p = ngx_cpymem(p, dir->data, dir->len);

    if (!ngx_path_separator(*(p - 1))) {
        file.len++;
        *p++ = '/';
    }

    p = ngx_hex_dump(p, qc->path->cid->id, qc->path->cid->len);

    p = ngx_cpymem(p, ".sqlog", sizeof(".sqlog") - 1);
    *p = '\0';

    qc->qlog->fd = ngx_open_file(file.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
                                 NGX_FILE_DEFAULT_ACCESS);

    if (qc->qlog->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &file);
        return NGX_ERROR;
    }

    qc->qlog->path = file;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_qlog_write_header(ngx_connection_t *c, ngx_quic_connection_t *qc,
    uint64_t reference_time_ms)
{
    u_char   *p, *end;
    u_char    buf[256];

    p = buf;
    end = buf + sizeof(buf);

    ngx_qlog_write_literal(p, end, "\x1e{\"qlog_version\":\"0.3\","
                           "\"qlog_format\":\"JSON-SEQ\","
                           "\"trace\":{\"common_fields\":{");
    ngx_qlog_write_pair_hex(p, end, "group_id",
                            qc->tp.original_dcid.data,
                            qc->tp.original_dcid.len);
    ngx_qlog_write_literal(p, end, ",\"time_format\":\"relative\",");
    ngx_qlog_write_pair_num(p, end, "reference_time", reference_time_ms);
    ngx_qlog_write_literal(p, end, "},\"vantage_point\":{\"name\":\"nginx\","
                           "\"type\":\"server\"}}}\n");

    return ngx_quic_qlog_write_buf(c, qc->qlog, buf, p - buf);
}


static const char *
ngx_quic_qlog_packet_name(uint8_t flags)
{
    if (ngx_quic_short_pkt(flags)) {
        return "1RTT";
    }

    switch (flags & NGX_QUIC_PKT_TYPE) {
    case NGX_QUIC_PKT_INITIAL:
        return "initial";
    case NGX_QUIC_PKT_ZRTT:
        return "0RTT";
    case NGX_QUIC_PKT_HANDSHAKE:
        return "handshake";
    case NGX_QUIC_PKT_RETRY:
        return "retry";
    default:
        return "unknown";
    }
}


static const char *
ngx_quic_qlog_packet_name_by_level(ngx_uint_t level)
{
    switch (level) {
    case NGX_QUIC_ENCRYPTION_INITIAL:
        return "initial";
    case NGX_QUIC_ENCRYPTION_HANDSHAKE:
        return "handshake";
    case NGX_QUIC_ENCRYPTION_APPLICATION:
        return "1RTT";
    default:
        return "unknown";
    }
}


static u_char *
ngx_quic_qlog_padding_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"padding\"}");
    return p;
}


static u_char *
ngx_quic_qlog_ping_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"ping\"}");
    return p;
}


static u_char *
ngx_quic_qlog_ack_frame(u_char *p, u_char *end, ngx_connection_t *c,
    ngx_quic_connection_t *qc, ngx_quic_frame_t *f)
{
    ssize_t                n;
    u_char                *pos, *last;
    uint64_t               min, max, gap, range;
    ngx_uint_t             i;
    ngx_quic_ack_frame_t  *ack;
    double                 ack_delay;

    ack = &f->u.ack;

    ack_delay = (double) (ack->delay << qc->ctp.ack_delay_exponent) / 1000.0;

    ngx_qlog_write(p, end, "{\"frame_type\":\"ack\",\"ack_delay\":%.3f"
                   ",\"acked_ranges\":[", ack_delay);

    if (ack->first_range > ack->largest) {
        ngx_qlog_write_literal(p, end, "]}");
        return p;
    }

    min = ack->largest - ack->first_range;
    max = ack->largest;

    if (min == max) {
        ngx_qlog_write(p, end, "[%uL]", min);
    } else {
        ngx_qlog_write(p, end, "[%uL,%uL]", min, max);
    }

    if (f->data) {
        pos  = f->data->buf->pos;
        last = f->data->buf->last;
    } else {
        pos = last = NULL;
    }

    for (i = 0; i < ack->range_count; i++) {

        n = ngx_quic_parse_ack_range(c->log, pos, last,
                                     &gap, &range);
        if (n == NGX_ERROR) {
            break;
        }
        pos += n;

        if (gap + 2 > min) {
            break;
        }

        max = min - gap - 2;

        if (range > max) {
            break;
        }

        min = max - range;

        if (min == max) {
            ngx_qlog_write(p, end, ",[%uL]", min);
        } else {
            ngx_qlog_write(p, end, ",[%uL,%uL]", min, max);
        }
    }

    ngx_qlog_write_char(p, end, ']');

    if (f->type == NGX_QUIC_FT_ACK_ECN) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ect1", ack->ect1);
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ect0", ack->ect0);
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_num(p, end, "ce", ack->ce);
    }

    ngx_qlog_write_char(p, end, '}');
    return p;
}


static u_char *
ngx_quic_qlog_reset_stream_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"reset_stream\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.reset_stream.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "error_code", f->u.reset_stream.error_code);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "final_size", f->u.reset_stream.final_size);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_stop_sending_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"stop_sending\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.stop_sending.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "error_code", f->u.stop_sending.error_code);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_crypto_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"crypto\",");
    ngx_qlog_write_pair_num(p, end, "offset", f->u.crypto.offset);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "length", f->u.crypto.length);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_new_token_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end,
                           "{\"frame_type\":\"new_token\", \"token\":{");
    ngx_qlog_write_pair_num(p, end, "length", f->u.token.length);
    ngx_qlog_write_char(p, end, '}');
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_stream_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"stream\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.stream.stream_id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "offset", f->u.stream.offset);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "length", f->u.stream.length);

    if (f->u.stream.fin) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_bool(p, end, "fin", 1);
    }
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_max_data_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"max_data\",");
    ngx_qlog_write_pair_num(p, end, "maximum", f->u.max_data.max_data);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_max_stream_data_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"max_stream_data\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.max_stream_data.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "maximum", f->u.max_stream_data.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_max_streams_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"max_streams\",");
    ngx_qlog_write_pair_num(p, end, "maximum", f->u.max_streams.limit);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "stream_type",
                            f->u.max_streams.bidi ? "bidirectional"
                                                  : "unidirectional");

    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_data_blocked_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"data_blocked\",");
    ngx_qlog_write_pair_num(p, end, "limit", f->u.data_blocked.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_stream_data_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"stream_data_blocked\",");
    ngx_qlog_write_pair_num(p, end, "stream_id", f->u.stream_data_blocked.id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "limit", f->u.stream_data_blocked.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_streams_blocked_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"streams_blocked\",");
    ngx_qlog_write_pair_str(p, end, "stream_type",
                            f->u.streams_blocked.bidi ? "bidirectional"
                                                      : "unidirectional");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "limit", f->u.streams_blocked.limit);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_new_connection_id_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"new_connection_id\",");
    ngx_qlog_write_pair_num(p, end, "sequence_number", f->u.ncid.seqnum);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "retire_prior_to", f->u.ncid.retire);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "connection_id_length", f->u.ncid.len);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_hex(p, end, "connection_id", f->u.ncid.cid,
                            f->u.ncid.len);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_hex(p, end, "stateless_reset_token", f->u.ncid.srt,
                            NGX_QUIC_SR_TOKEN_LEN);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_retire_connection_id_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end,
                           "{\"frame_type\":\"retire_connection_id\",");
    ngx_qlog_write_pair_num(p, end, "sequence_number",
                            f->u.retire_cid.sequence_number);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_path_challenge_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"path_challenge\",");
    ngx_qlog_write_pair_hex(p, end, "data", f->u.path_challenge.data,
                            sizeof(f->u.path_challenge.data));
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_path_response_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"path_response\",");
    ngx_qlog_write_pair_hex(p, end, "data", f->u.path_response.data,
                            sizeof(f->u.path_response.data));
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_connection_close_frame(u_char *p, u_char *end,
    ngx_quic_frame_t *f)
{
    ngx_uint_t  is_app;

    is_app = (f->type == NGX_QUIC_FT_CONNECTION_CLOSE_APP);

    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"connection_close\",");
    ngx_qlog_write_pair_str(p, end, "error_space", is_app ? "application"
                                                          : "transport");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "error_code", f->u.close.error_code);

    if (f->u.close.reason.len > 0) {
        ngx_qlog_write_char(p, end, ',');
        ngx_qlog_write_pair_strv(p, end, "reason", &f->u.close.reason);
    }

    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_quic_qlog_handshake_done_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    ngx_qlog_write_literal(p, end, "{\"frame_type\":\"handshake_done\"}");
    return p;
}
