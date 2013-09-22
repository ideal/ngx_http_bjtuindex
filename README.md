# ngx_auto_keepalive

autoindex module for mirror.bjtu.edu.cn, with nicer style.

Installation Instructions
=========================

Build and install by running in nginx directory:

```
./configure --add-module=/path/to/ngx_http_bjtuindex
```

Configuration
=============

In main, server or location config:
```
    bjtuindex on;
```