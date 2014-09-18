incwndcheck
===========

Test initcwnd for any http endpoint (Linux only)

Usage
-----

```
go build github.com/turbobytes/initcwndcheck
wget -O homepage.html https://github.com/turbobytes/initcwndcheck/raw/master/homepage.html
sudo ./initcwndcheck
```

In browser open http://127.0.0.1:8565/