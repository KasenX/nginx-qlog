#ifndef _NGX_EVENT_QUIC_QLOG_H_INCLUDED_
#define _NGX_EVENT_QUIC_QLOG_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_QLOG_BUF_SIZE  4096


typedef struct ngx_quic_qlog_s  ngx_quic_qlog_t;

typedef enum {
  NGX_QUIC_QLOG_SIDE_LOCAL,
  NGX_QUIC_QLOG_SIDE_REMOTE,
} ngx_quic_qlog_side_e;

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


ngx_int_t
ngx_quic_qlog_init(ngx_connection_t *c, ngx_quic_connection_t *qc);

void
ngx_quic_qlog_parameters_set(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_tp_t *params, ngx_quic_qlog_side_e side);

void
ngx_quic_qlog_recovery_parameters_set(ngx_connection_t *c,
    ngx_quic_connection_t *qc);

void
ngx_quic_qlog_metrics_updated(ngx_connection_t *c, ngx_quic_connection_t *qc);

void
ngx_quic_qlog_pkt_received_start(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
void
ngx_quic_qlog_pkt_received_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);

void
ngx_quic_qlog_pkt_sent_start(ngx_connection_t *c, ngx_quic_connection_t *qc);
void
ngx_quic_qlog_pkt_sent_end(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);

void
ngx_quic_qlog_write_frame(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_frame_t *f);

#endif /* _NGX_EVENT_QUIC_QLOG_H_INCLUDED_ */
