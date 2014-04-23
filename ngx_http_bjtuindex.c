
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 *
 * Copyright (C) Shang Yuanchun <idealities@gmail.com>
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t      name;
    size_t         utf_len;
    size_t         escape;
    size_t         escape_html;

    unsigned       dir:1;

    time_t         mtime;
    off_t          size;
} ngx_http_bjtuindex_entry_t;


typedef struct {
    ngx_flag_t     enable;
    ngx_flag_t     localtime;
    ngx_flag_t     exact_size;
    ngx_str_t      css_path;
} ngx_http_bjtuindex_loc_conf_t;


#define NGX_HTTP_AUTOINDEX_PREALLOCATE  50

#define NGX_HTTP_AUTOINDEX_NAME_LEN     50


static int ngx_libc_cdecl ngx_http_bjtuindex_cmp_entries(const void *one,
    const void *two);
static ngx_int_t ngx_http_bjtuindex_error(ngx_http_request_t *r,
    ngx_dir_t *dir, ngx_str_t *name);
static ngx_int_t ngx_http_bjtuindex_init(ngx_conf_t *cf);
static void *ngx_http_bjtuindex_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_bjtuindex_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_bjtuindex_commands[] = {

    { ngx_string("bjtuindex"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_bjtuindex_loc_conf_t, enable),
      NULL },

    { ngx_string("autoindex_localtime"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_bjtuindex_loc_conf_t, localtime),
      NULL },

    { ngx_string("autoindex_exact_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_bjtuindex_loc_conf_t, exact_size),
      NULL },

    { ngx_string("bjtuindex_css_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_bjtuindex_loc_conf_t, css_path),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_bjtuindex_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_bjtuindex_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_bjtuindex_create_loc_conf,    /* create location configuration */
    ngx_http_bjtuindex_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_bjtuindex_module = {
    NGX_MODULE_V1,
    &ngx_http_bjtuindex_module_ctx,        /* module context */
    ngx_http_bjtuindex_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char title[] =
"<html>" CRLF
"<head>" CRLF
"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" >" CRLF
"<link href=\"";

static u_char css[]   =
"\" rel=\"stylesheet\" type=\"text/css\" />" CRLF
"<style type=\"text/css\"> \
table { \
      border: none; \
      padding: 0; \
      margin 0; \
      } \
      th { \
      text-align: left; \
      white-space: nowrap; \
      border-bottom: 1px solid #DADADA; \
      argin: 0; \
      background-color: #F6F6F6; \
      padding: 4px; \
      } \
      td { \
      padding: 4px; \
      border-bottom: 1px solid #EEE; \
      margin: 0; \
      } \
      td.date { \
      white-space: nowrap; \
      text-align: right; \
      }" CRLF
"</style>" CRLF
"<title>Index of "
;


static u_char header[] =
"</title></head>" CRLF
"<div id=\"header\">" CRLF
"<h1><a href=\"/cn/index.html\" title=\"BJTU free and open source software mirror\"><span>BJTU mirror</span></a></h1>" CRLF
"<ul>" CRLF
"<li><a class=\"tab-home highlight-gray\" href=\"/cn/index.html\" title=\"Home\">Home</a></li>" CRLF
"<li><a class=\"tab-update highlight-yellow\" href=\"/cn/update.html\" title=\"Update history\">Update</a></li>" CRLF
"<li><a class=\"tab-news highlight-purple\" href=\"/cn/news.html\" title=\"News\">News</a></li>" CRLF
"<li><a class=\"tab-howto highlight-red\" href=\"/cn/howto.html\" title=\"How to use\">Howto</a></li>" CRLF
"<li><a class=\"tab-stat highlight-green\" href=\"/cn/stat.html\" title=\"User statistic\">Statistic</a></li>" CRLF
"<li><a class=\"tab-flow highlight-blue\" href=\"/cn/flow.html\" title=\"Flow\">Flow</a></li>" CRLF
"</ul>" CRLF
"</div>" CRLF
"<div id=\"headline\">" CRLF
"<h4> Index of "
;

static u_char tail[] =
"</div>" CRLF
"</div>" CRLF
"</div>" CRLF
"<div id=\"footer\">" CRLF
"<p>CopyLeft &copy; 2005 - 2013 <a href=\"http://mirror.bjtu.edu.cn\">BJTU</a>.</p>" CRLF
"</div>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static ngx_int_t
ngx_http_bjtuindex_handler(ngx_http_request_t *r)
{
    u_char                         *last, *filename, scale;
    off_t                           length;
    size_t                          len, char_len, escape_html, allocated, root;
    ngx_tm_t                        tm;
    ngx_err_t                       err;
    ngx_buf_t                      *b;
    ngx_int_t                       rc, size;
    ngx_str_t                       path;
    ngx_dir_t                       dir;
    ngx_uint_t                      i, level, utf8;
    ngx_pool_t                     *pool;
    ngx_time_t                     *tp;
    ngx_chain_t                     out;
    ngx_array_t                     entries;
    ngx_http_bjtuindex_entry_t     *entry;
    ngx_http_bjtuindex_loc_conf_t  *alcf;

    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_bjtuindex_module);

    if (!alcf->enable) {
        return NGX_DECLINED;
    }

    /* NGX_DIR_MASK_LEN is lesser than NGX_HTTP_AUTOINDEX_PREALLOCATE */

    last = ngx_http_map_uri_to_path(r, &path, &root,
                                    NGX_HTTP_AUTOINDEX_PREALLOCATE);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len  = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http bjtuindex: \"%s\"", path.data);

    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        err = ngx_errno;

        if (err == NGX_ENOENT
            || err == NGX_ENOTDIR
            || err == NGX_ENAMETOOLONG)
        {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

#if (NGX_SUPPRESS_WARN)

    /* MSVC thinks 'entries' may be used without having been initialized */
    ngx_memzero(&entries, sizeof(ngx_array_t));

#endif

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    if (ngx_array_init(&entries, pool, 40, sizeof(ngx_http_bjtuindex_entry_t))
        != NGX_OK)
    {
        return ngx_http_bjtuindex_error(r, &dir, &path);
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("text/html") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/html");

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        if (ngx_close_dir(&dir) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_dir_n " \"%V\" failed", &path);
        }

        return rc;
    }

    filename = path.data;
    filename[path.len] = '/';

    if (r->headers_out.charset.len == 5
        && ngx_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
           == 0)
    {
        utf8 = 1;

    } else {
        utf8 = 0;
    }

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                              ngx_read_dir_n " \"%V\" failed", &path);
                return ngx_http_bjtuindex_error(r, &dir, &path);
            }

            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http bjtuindex file: \"%s\"", ngx_de_name(&dir));

        len = ngx_de_namelen(&dir);

        if (ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        if (!dir.valid_info) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + NGX_HTTP_AUTOINDEX_PREALLOCATE;

                filename = ngx_pnalloc(pool, allocated);
                if (filename == NULL) {
                    return ngx_http_bjtuindex_error(r, &dir, &path);
                }

                last = ngx_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            ngx_cpystrn(last, ngx_de_name(&dir), len + 1);

            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOENT && err != ENX_ELOOP) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                  ngx_de_info_n " \"%s\" failed", filename);

                    if (err == NGX_EACCES) {
                        continue;
                    }

                    return ngx_http_bjtuindex_error(r, &dir, &path);
                }

                if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                                  ngx_de_link_info_n " \"%s\" failed",
                                  filename);
                    return ngx_http_bjtuindex_error(r, &dir, &path);
                }
            }
        }

        entry = ngx_array_push(&entries);
        if (entry == NULL) {
            return ngx_http_bjtuindex_error(r, &dir, &path);
        }

        entry->name.len = len;

        entry->name.data = ngx_pnalloc(pool, len + 1);
        if (entry->name.data == NULL) {
            return ngx_http_bjtuindex_error(r, &dir, &path);
        }

        ngx_cpystrn(entry->name.data, ngx_de_name(&dir), len + 1);

        entry->escape = 2 * ngx_escape_uri(NULL, ngx_de_name(&dir), len,
                                           NGX_ESCAPE_URI_COMPONENT);

        entry->escape_html = ngx_escape_html(NULL, entry->name.data,
                                             entry->name.len);

        if (utf8) {
            entry->utf_len = ngx_utf8_length(entry->name.data, entry->name.len);
        } else {
            entry->utf_len = len;
        }

        entry->dir = ngx_de_is_dir(&dir);
        entry->mtime = ngx_de_mtime(&dir);
        entry->size = ngx_de_size(&dir);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", &path);
    }

    escape_html = ngx_escape_html(NULL, r->uri.data, r->uri.len);

    len = sizeof(title) - 1
          + alcf->css_path.len
          + sizeof(css) - 1
          + r->uri.len + escape_html
          + sizeof(header) - 1
          + r->uri.len + escape_html
          + sizeof("</h4></div>") - 1
          + sizeof("<div id=\"page\"><div id=\"simple-page\">"
                   "<div class=\"main\"><table><tr><td>"
                   "<a href=\"../\">../</a></td></tr>" CRLF) - 1
          + sizeof("</table>") - 1
          + sizeof(tail) - 1;

    entry = entries.elts;
    for (i = 0; i < entries.nelts; i++) {
        len += sizeof("<tr><td><a href=\"") - 1
            + entry[i].name.len + entry[i].escape
            + 1                                          /* 1 is for "/" */
            + sizeof("\">") - 1
            + entry[i].name.len - entry[i].utf_len
            + entry[i].escape_html
            + NGX_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
            + sizeof("</a></td>") - 1
            + sizeof("<td>28-Sep-1970 12:00</td>") - 1
            + sizeof("<td></td></tr>") - 1
            + 20                                         /* the file size */
            + 2;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (entries.nelts > 1) {
        ngx_qsort(entry, (size_t) entries.nelts,
                  sizeof(ngx_http_bjtuindex_entry_t),
                  ngx_http_bjtuindex_cmp_entries);
    }

    b->last = ngx_cpymem(b->last, title, sizeof(title) - 1);
    b->last = ngx_cpymem(b->last, alcf->css_path.data, alcf->css_path.len);
    b->last = ngx_cpymem(b->last, css, sizeof(css) - 1);

    if (escape_html) {
        b->last = (u_char *) ngx_escape_html(b->last, r->uri.data, r->uri.len);
        b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
        b->last = (u_char *) ngx_escape_html(b->last, r->uri.data, r->uri.len);

    } else {
        b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
        b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
        b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
    }

    b->last = ngx_cpymem(b->last, "</h4></div>", sizeof("</h4></div>") - 1);

    b->last = ngx_cpymem(b->last, "<div id=\"page\"><div id=\"simple-page\">"
                                  "<div class=\"main\">"
                                  "<table><tr><td><a href=\"../\">../</a></td></tr>" CRLF,
                         sizeof("<div id=\"page\"><div id=\"simple-page\">"
                                "<div class=\"main\">"
                                "<table><tr><td><a href=\"../\">../</a></td></tr>" CRLF) - 1);

    tp = ngx_timeofday();

    for (i = 0; i < entries.nelts; i++) {
        b->last = ngx_cpymem(b->last, "<tr><td><a href=\"", sizeof("<tr><td><a href=\"") - 1);

        if (entry[i].escape) {
            ngx_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                           NGX_ESCAPE_URI_COMPONENT);

            b->last += entry[i].name.len + entry[i].escape;

        } else {
            b->last = ngx_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';
        *b->last++ = '>';

        len = entry[i].utf_len;

        if (entry[i].name.len != len) {
            if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
                char_len = NGX_HTTP_AUTOINDEX_NAME_LEN - 3 + 1;

            } else {
                char_len = NGX_HTTP_AUTOINDEX_NAME_LEN + 1;
            }

            last = b->last;
            b->last = ngx_utf8_cpystrn(b->last, entry[i].name.data,
                                       char_len, entry[i].name.len + 1);

            if (entry[i].escape_html) {
                b->last = (u_char *) ngx_escape_html(last, entry[i].name.data,
                                                     b->last - last);
            }

            last = b->last;

        } else {
            if (entry[i].escape_html) {
                if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
                    char_len = NGX_HTTP_AUTOINDEX_NAME_LEN - 3;

                } else {
                    char_len = len;
                }

                b->last = (u_char *) ngx_escape_html(b->last,
                                                  entry[i].name.data, char_len);
                last = b->last;

            } else {
                b->last = ngx_cpystrn(b->last, entry[i].name.data,
                                      NGX_HTTP_AUTOINDEX_NAME_LEN + 1);
                last = b->last - 3;
            }
        }

        if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
            b->last = ngx_cpymem(last, "..&gt;</a></td>", sizeof("..&gt;</a></td>") - 1);

        } else {
            if (entry[i].dir && NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                *b->last++ = '/';
                len++;
            }

            b->last = ngx_cpymem(b->last, "</a></td>", sizeof("</a></td>") - 1);
            ngx_memset(b->last, ' ', NGX_HTTP_AUTOINDEX_NAME_LEN - len);
            b->last += NGX_HTTP_AUTOINDEX_NAME_LEN - len;
        }

        ngx_gmtime(entry[i].mtime + tp->gmtoff * 60 * alcf->localtime, &tm);

        b->last = ngx_sprintf(b->last, "<td>%02d-%s-%d %02d:%02d</td>",
                              tm.ngx_tm_mday,
                              months[tm.ngx_tm_mon - 1],
                              tm.ngx_tm_year,
                              tm.ngx_tm_hour,
                              tm.ngx_tm_min);

        b->last = ngx_cpymem(b->last, "<td>", sizeof("<td>") - 1);
        if (alcf->exact_size) {
            if (entry[i].dir) {
                b->last = ngx_cpymem(b->last,  "                  -",
                                     sizeof("                  -") - 1);
            } else {
                b->last = ngx_sprintf(b->last, "%19O", entry[i].size);
            }

        } else {
            if (entry[i].dir) {
                b->last = ngx_cpymem(b->last,  "      -",
                                     sizeof("      -") - 1);

            } else {
                length = entry[i].size;

                if (length > 1024 * 1024 * 1024 - 1) {
                    size = (ngx_int_t) (length / (1024 * 1024 * 1024));
                    if ((length % (1024 * 1024 * 1024))
                                                > (1024 * 1024 * 1024 / 2 - 1))
                    {
                        size++;
                    }
                    scale = 'G';

                } else if (length > 1024 * 1024 - 1) {
                    size = (ngx_int_t) (length / (1024 * 1024));
                    if ((length % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
                        size++;
                    }
                    scale = 'M';

                } else if (length > 9999) {
                    size = (ngx_int_t) (length / 1024);
                    if (length % 1024 > 511) {
                        size++;
                    }
                    scale = 'K';

                } else {
                    size = (ngx_int_t) length;
                    scale = '\0';
                }

                if (scale) {
                    b->last = ngx_sprintf(b->last, "%6i%c", size, scale);

                } else {
                    b->last = ngx_sprintf(b->last, " %6i", size);
                }
            }
        }
        b->last = ngx_cpymem(b->last, "</td></tr>", sizeof("</td></tr>") - 1);

        *b->last++ = CR;
        *b->last++ = LF;
    }

    /* TODO: free temporary pool */

    b->last = ngx_cpymem(b->last, "</table>", sizeof("</table>") - 1);

    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static int ngx_libc_cdecl
ngx_http_bjtuindex_cmp_entries(const void *one, const void *two)
{
    ngx_http_bjtuindex_entry_t *first  = (ngx_http_bjtuindex_entry_t *) one;
    ngx_http_bjtuindex_entry_t *second = (ngx_http_bjtuindex_entry_t *) two;

    if (first->dir && !second->dir) {
        /* move the directories to the start */
        return -1;
    }

    if (!first->dir && second->dir) {
        /* move the directories to the start */
        return 1;
    }

    return (int) ngx_strcmp(first->name.data, second->name.data);
}

static ngx_int_t
ngx_http_bjtuindex_error(ngx_http_request_t *r, ngx_dir_t *dir, ngx_str_t *name)
{
    if (ngx_close_dir(dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", name);
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
ngx_http_bjtuindex_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_bjtuindex_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_bjtuindex_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable     = NGX_CONF_UNSET;
    conf->localtime  = NGX_CONF_UNSET;
    conf->exact_size = NGX_CONF_UNSET;
#if 0
    conf->css_path   = ngx_null_string;
#endif

    return conf;
}


static char *
ngx_http_bjtuindex_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_bjtuindex_loc_conf_t *prev = parent;
    ngx_http_bjtuindex_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->localtime, prev->localtime, 0);
    ngx_conf_merge_value(conf->exact_size, prev->exact_size, 1);
    ngx_conf_merge_str_value(conf->css_path, prev->css_path, "/style.css");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_bjtuindex_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_bjtuindex_handler;

    return NGX_OK;
}
