1. Compile project

``` shell
go build main.go
```

1. Copy the service to `/usr/lib/systemd/system/cas-auth-go.service`:

1. Reload service, enable it 

```bash
systemctl daemon-reload
systemctl enable cas-auth-go
systemctl start cas-auth-go
```