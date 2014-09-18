incwndcheck
===========

Test initcwnd for any http endpoint (Linux only).

What this basically does is makes a tcp connection, sends a GET request. From now on it stops acknowledging packets from the remote host allowing us to measure how much data the server is willing to send unacknowledged.

Read more about initial congession windows : http://www.cdnplanet.com/blog/tune-tcp-initcwnd-for-optimum-performance/

Usage
-----

```
go build github.com/turbobytes/initcwndcheck
wget -O homepage.html https://github.com/turbobytes/initcwndcheck/raw/master/homepage.html
sudo ./initcwndcheck
```

In browser open http://127.0.0.1:8565/

JSON API
--------

/runtest?url=http%3A//www.cdnplanet.com/

Limitations
-----------

1. Works on Linux only, because some iptables commands are hardcoded in the code. In future I will split that to platform specific modules.
2. We send receive window of 65535
3. Works on HTTP only. No https/tls support at this time.
4. Server might send a smaller payload than expected (e.g. in case of error). Inspect hexdump to be sure

Coming Soon
-----------

A CLI tool to run one-off tests
