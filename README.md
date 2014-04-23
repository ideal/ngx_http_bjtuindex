# ngx_http_bjtuindex

autoindex module for mirror.bjtu.edu.cn, with nicer style.

Installation Instructions
=========================

Build and install by running in nginx directory:

```
./configure --add-module=/path/to/ngx_http_bjtuindex
```

NOTE: Currently before make you need to edit `objs/ngx_modules.c`, just
put `&ngx_http_bjtuindex_module` ahead of `&ngx_http_autoindex_module`.

Configuration
=============

In main, server or location config:
```
    bjtuindex on;
    bjtuindex_css_path "/cn/style.css";
```
