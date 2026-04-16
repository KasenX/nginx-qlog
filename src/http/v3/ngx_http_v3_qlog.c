/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_quic.h>
#include <ngx_event_quic_connection.h>
#include <ngx_event_quic_qlog.h>
#include <ngx_http_v3_qlog.h>


#if (NGX_QUIC_QLOG)


static const char *ngx_http_v3_qlog_stream_type_str[] = {
    "control",
    "push",
    "qpack_encode",
    "qpack_decode",
    "reserved",
    "unknown",
    "request"
};


static ngx_quic_qlog_t *ngx_http_v3_qlog_start_frame_event(
    ngx_connection_t *c, u_char **pp, u_char **pend, const char *event_name,
    uint64_t stream_id, size_t length, const char *frame_type);
static u_char *ngx_http_v3_qlog_write_header(u_char *p, u_char *end,
    u_char *name, size_t name_len, u_char *value, size_t value_len);
static u_char *ngx_http_v3_qlog_write_setting(u_char *p, u_char *end,
    uint64_t id, uint64_t value);
static u_char *ngx_qlog_write_json_str(u_char *p, u_char *end, u_char *data,
    size_t len);


static ngx_quic_qlog_t *
ngx_http_v3_get_qlog(ngx_connection_t *c)
{
    ngx_connection_t       *parent;
    ngx_quic_connection_t  *qc;

    if (c->quic == NULL) {
        return NULL;
    }

    parent = c->quic->parent;
    if (parent == NULL) {
        return NULL;
    }

    qc = ngx_quic_get_connection(parent);
    if (qc == NULL) {
        return NULL;
    }

    return qc->qlog;
}


static const char *
ngx_http_v3_qlog_param_name(uint64_t id)
{
    switch (id) {
    case 0x01:
        return "max_table_capacity";
    case 0x06:
        return "max_field_section_size";
    case 0x07:
        return "blocked_streams";
    default:
        return NULL;
    }
}


static ngx_quic_qlog_t *
ngx_http_v3_qlog_start_frame_event(ngx_connection_t *c, u_char **pp,
    u_char **pend, const char *event_name, uint64_t stream_id, size_t length,
    const char *frame_type)
{
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(ngx_http_v3_get_qlog(c), pp, pend,
                                     NGX_QUIC_QLOG_LEVEL_CORE, event_name);
    if (qlog == NULL) {
        return NULL;
    }

    ngx_qlog_write_pair_num(*pp, *pend, "stream_id", stream_id);
    ngx_qlog_write_char(*pp, *pend, ',');
    ngx_qlog_write_pair_num(*pp, *pend, "length", length);
    ngx_qlog_write_literal(*pp, *pend, ",\"frame\":{");
    ngx_qlog_write_pair_str(*pp, *pend, "frame_type", frame_type);

    return qlog;
}


static u_char *
ngx_http_v3_qlog_write_header(u_char *p, u_char *end, u_char *name,
    size_t name_len, u_char *value, size_t value_len)
{
    ngx_qlog_write_literal(p, end, "{\"name\":");
    p = ngx_qlog_write_json_str(p, end, name, name_len);
    ngx_qlog_write_literal(p, end, ",\"value\":");
    p = ngx_qlog_write_json_str(p, end, value, value_len);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


static u_char *
ngx_http_v3_qlog_write_setting(u_char *p, u_char *end, uint64_t id,
    uint64_t value)
{
    u_char        name[NGX_INT64_LEN + 1];
    uintptr_t     n;
    const char   *param_name;

    ngx_qlog_write_literal(p, end, "{\"name\":");

    param_name = ngx_http_v3_qlog_param_name(id);

    if (param_name != NULL) {
        ngx_qlog_write_char(p, end, '"');
        p = ngx_cpymem(p, param_name,
                       ngx_min((size_t) (end - p), ngx_strlen(param_name)));
        ngx_qlog_write_char(p, end, '"');
    } else {
        n = ngx_sprintf(name, "%uL", id) - name;
        p = ngx_qlog_write_json_str(p, end, name, n);
    }

    ngx_qlog_write_literal(p, end, ",\"value\":");
    ngx_qlog_write(p, end, "%uL", value);
    ngx_qlog_write_char(p, end, '}');

    return p;
}


void
ngx_http_v3_qlog_parameters_set_local(ngx_connection_t *c,
    uint64_t max_table_capacity, uint64_t blocked_streams)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(ngx_http_v3_get_qlog(c), &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_BASE,
                                     "http:parameters_set");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_pair_str(p, end, "owner", "local");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "max_table_capacity", max_table_capacity);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "blocked_streams", blocked_streams);

    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_parameters_set_remote(ngx_connection_t *c,
    uint64_t id, uint64_t value)
{
    u_char           *p, *end;
    const char       *name;
    ngx_quic_qlog_t  *qlog;

    name = ngx_http_v3_qlog_param_name(id);
    if (name == NULL) {
        /* skip unknown parameters */
        return;
    }

    qlog = ngx_quic_qlog_start_event(ngx_http_v3_get_qlog(c), &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_BASE,
                                     "http:parameters_set");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_pair_str(p, end, "owner", "remote");
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "parameter", name);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "value", value);

    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_stream_type_set(ngx_connection_t *c, uint64_t stream_id,
    ngx_http_v3_qlog_stream_type_e stream_type)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_quic_qlog_start_event(ngx_http_v3_get_qlog(c), &p, &end,
                                     NGX_QUIC_QLOG_LEVEL_BASE,
                                     "http:stream_type_set");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_pair_num(p, end, "stream_id", stream_id);
    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_str(p, end, "stream_type",
                            ngx_http_v3_qlog_stream_type_str[stream_type]);

    ngx_qlog_write_literal(p, end, "}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_created_settings(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t max_table_capacity,
    uint64_t blocked_streams)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_created",
                                              stream_id, length, "settings");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, ",\"settings\":[");
    p = ngx_http_v3_qlog_write_setting(p, end,
                                       NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY,
                                       max_table_capacity);
    ngx_qlog_write_char(p, end, ',');
    p = ngx_http_v3_qlog_write_setting(p, end,
                                       NGX_HTTP_V3_PARAM_BLOCKED_STREAMS,
                                       blocked_streams);
    ngx_qlog_write_char(p, end, ']');

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_created_goaway(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t id)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_created",
                                              stream_id, length, "goaway");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "id", id);

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_created_headers(ngx_http_request_t *r, size_t length)
{
    u_char           *p, *end;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(r->connection, &p, &end,
                                              "http:frame_created",
                                              r->connection->quic->id, length,
                                              "headers");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, ",\"headers\":[");

    /* :status pseudo-header */
    p = ngx_slprintf(p, end, "{\"name\":\":status\",\"value\":\"%03ui\"}",
                     r->headers_out.status);

    /* iterate through headers_out.headers list */
    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        ngx_qlog_write_char(p, end, ',');
        p = ngx_http_v3_qlog_write_header(p, end, header[i].key.data,
                                          header[i].key.len,
                                          header[i].value.data,
                                          header[i].value.len);
    }

    ngx_qlog_write_literal(p, end, "]}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_created_data(ngx_connection_t *c,
    uint64_t stream_id, size_t length)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_created",
                                              stream_id, length, "data");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_settings(ngx_connection_t *c,
    uint64_t stream_id, size_t length, ngx_array_t *settings)
{
    u_char                       *p, *end;
    ngx_uint_t                    i;
    ngx_quic_qlog_t              *qlog;
    ngx_http_v3_qlog_setting_t   *setting;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, length, "settings");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, ",\"settings\":[");

    if (settings != NULL) {
        setting = settings->elts;

        for (i = 0; i < settings->nelts; i++) {
            if (i != 0) {
                ngx_qlog_write_char(p, end, ',');
            }

            p = ngx_http_v3_qlog_write_setting(p, end, setting[i].id,
                                               setting[i].value);
        }
    }

    ngx_qlog_write_char(p, end, ']');

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_goaway(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t id)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, length, "goaway");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "id", id);

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_max_push_id(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t push_id)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, length,
                                              "max_push_id");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "push_id", push_id);

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_cancel_push(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t push_id)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, length,
                                              "cancel_push");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "push_id", push_id);

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_reserved(ngx_connection_t *c,
    uint64_t stream_id)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, 0, "reserved");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_unknown(ngx_connection_t *c,
    uint64_t stream_id, size_t length, uint64_t raw_frame_type)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, length, "unknown");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_char(p, end, ',');
    ngx_qlog_write_pair_num(p, end, "raw_frame_type", raw_frame_type);

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_headers(ngx_http_request_t *r, size_t length)
{
    u_char           *p, *end;
    ngx_uint_t        i;
    ngx_str_t         path;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(r->connection, &p, &end,
                                              "http:frame_parsed",
                                              r->connection->quic->id, length,
                                              "headers");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, ",\"headers\":[");

    /* :method pseudo-header */
    p = ngx_http_v3_qlog_write_header(p, end, (u_char *) ":method",
                                      sizeof(":method") - 1,
                                      r->method_name.data,
                                      r->method_name.len);

    /* :scheme pseudo-header */
    ngx_qlog_write_char(p, end, ',');
    p = ngx_http_v3_qlog_write_header(p, end, (u_char *) ":scheme",
                                      sizeof(":scheme") - 1,
                                      r->schema.data, r->schema.len);

    /* :authority pseudo-header */
    ngx_qlog_write_char(p, end, ',');
    p = ngx_http_v3_qlog_write_header(p, end, (u_char *) ":authority",
                                      sizeof(":authority") - 1,
                                      r->headers_in.server.data,
                                      r->headers_in.server.len);

    /* :path pseudo-header */
    if (r->uri_start && r->uri_end) {
        path.data = r->uri_start;
        path.len = r->uri_end - r->uri_start;
        ngx_qlog_write_char(p, end, ',');
        p = ngx_http_v3_qlog_write_header(p, end, (u_char *) ":path",
                                          sizeof(":path") - 1,
                                          path.data, path.len);
    }

    /* iterate through headers_in.headers list */
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        ngx_qlog_write_char(p, end, ',');
        p = ngx_http_v3_qlog_write_header(p, end, header[i].key.data,
                                          header[i].key.len,
                                          header[i].value.data,
                                          header[i].value.len);
    }

    ngx_qlog_write_literal(p, end, "]}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


void
ngx_http_v3_qlog_frame_parsed_data(ngx_connection_t *c,
    uint64_t stream_id, size_t length)
{
    u_char           *p, *end;
    ngx_quic_qlog_t  *qlog;

    qlog = ngx_http_v3_qlog_start_frame_event(c, &p, &end,
                                              "http:frame_parsed",
                                              stream_id, length, "data");
    if (qlog == NULL) {
        return;
    }

    ngx_qlog_write_literal(p, end, "}}}\n");

    ngx_quic_qlog_write(qlog, qlog->last, p - qlog->last);
}


static u_char *
ngx_qlog_write_json_str(u_char *p, u_char *end, u_char *data, size_t len)
{
    size_t     needed;
    uintptr_t  n;

    n = ngx_escape_json(NULL, data, len);
    needed = 2 + len + (size_t) n;

    if (p + needed <= end) {
        *p++ = '"';
        p = (u_char *) ngx_escape_json(p, data, len);
        *p++ = '"';
    } else if ((size_t) (end - p) >= 2) {
        /* not enough space - write empty string to keep JSON valid */
        ngx_qlog_write_char(p, end, '"');
        ngx_qlog_write_char(p, end, '"');
    }

    return p;
}


#endif /* NGX_QUIC_QLOG */
