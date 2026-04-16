/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_QLOG_H_INCLUDED_
#define _NGX_HTTP_V3_QLOG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_http_request_s  ngx_http_request_t;

typedef struct {
    uint64_t  id;
    uint64_t  value;
} ngx_http_v3_qlog_setting_t;


#if (NGX_QUIC_QLOG)


typedef enum {
    NGX_HTTP_V3_QLOG_STREAM_CONTROL = 0,
    NGX_HTTP_V3_QLOG_STREAM_PUSH,
    NGX_HTTP_V3_QLOG_STREAM_QPACK_ENCODE,
    NGX_HTTP_V3_QLOG_STREAM_QPACK_DECODE,
    NGX_HTTP_V3_QLOG_STREAM_RESERVED,
    NGX_HTTP_V3_QLOG_STREAM_UNKNOWN,
    NGX_HTTP_V3_QLOG_STREAM_REQUEST
} ngx_http_v3_qlog_stream_type_e;


void ngx_http_v3_qlog_parameters_set_local(ngx_connection_t *c,
    uint64_t max_table_capacity, uint64_t blocked_streams);
void ngx_http_v3_qlog_parameters_set_remote(ngx_connection_t *c,
    uint64_t id, uint64_t value);
void ngx_http_v3_qlog_stream_type_set(ngx_connection_t *c, uint64_t stream_id,
    ngx_http_v3_qlog_stream_type_e stream_type);

void ngx_http_v3_qlog_frame_created_settings(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t max_table_capacity,
    uint64_t blocked_streams);
void ngx_http_v3_qlog_frame_created_goaway(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t id);
void ngx_http_v3_qlog_frame_created_headers(ngx_http_request_t *r,
    size_t length);
void ngx_http_v3_qlog_frame_created_data(ngx_connection_t *c,
    uint64_t stream_id, size_t length);

void ngx_http_v3_qlog_frame_parsed_settings(ngx_connection_t *c,
    uint64_t stream_id, size_t length, ngx_array_t *settings);
void ngx_http_v3_qlog_frame_parsed_goaway(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t id);
void ngx_http_v3_qlog_frame_parsed_max_push_id(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t push_id);
void ngx_http_v3_qlog_frame_parsed_cancel_push(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t push_id);
void ngx_http_v3_qlog_frame_parsed_reserved(ngx_connection_t *c,
    uint64_t stream_id);
void ngx_http_v3_qlog_frame_parsed_unknown(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t raw_frame_type);
void ngx_http_v3_qlog_frame_parsed_headers(ngx_http_request_t *r,
    size_t length);
void ngx_http_v3_qlog_frame_parsed_data(ngx_connection_t *c,
    uint64_t stream_id, size_t length);

#else /* NGX_QUIC_QLOG */

#define ngx_http_v3_qlog_parameters_set_local(c, mtc, bs)
#define ngx_http_v3_qlog_parameters_set_remote(c, id, value)
#define ngx_http_v3_qlog_stream_type_set(c, stream_id, stream_type)

#define ngx_http_v3_qlog_frame_created_settings(c, sid, len, mtc, bs)
#define ngx_http_v3_qlog_frame_created_goaway(c, sid, len, id)
#define ngx_http_v3_qlog_frame_created_headers(r, len)
#define ngx_http_v3_qlog_frame_created_data(c, sid, len)

#define ngx_http_v3_qlog_frame_parsed_settings(c, sid, len, settings)
#define ngx_http_v3_qlog_frame_parsed_goaway(c, sid, len, id)
#define ngx_http_v3_qlog_frame_parsed_max_push_id(c, sid, len, push_id)
#define ngx_http_v3_qlog_frame_parsed_cancel_push(c, sid, len, push_id)
#define ngx_http_v3_qlog_frame_parsed_reserved(c, sid)
#define ngx_http_v3_qlog_frame_parsed_unknown(c, sid, len, raw_frame_type)
#define ngx_http_v3_qlog_frame_parsed_headers(r, len)
#define ngx_http_v3_qlog_frame_parsed_data(c, sid, len)

#endif /* NGX_QUIC_QLOG */


#endif /* _NGX_HTTP_V3_QLOG_H_INCLUDED_ */
