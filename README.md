# cnfse

HTTP virtual host confusion tool

## Usage

```
usage: cnfse.py [-h] -d DEST_HOST [-p DEST_PORT] [-l LISTEN_HOST] [-P LISTEN_PORT] -i INJECT_HOST [-r] [-o OVERRIDE_HOST] [-X]
                [-v]

HTTP virtual host confusion tool

options:
  -h, --help            show this help message and exit
  -d DEST_HOST, --dest-host DEST_HOST
                        destination host (default: None)
  -p DEST_PORT, --dest-port DEST_PORT
                        destination port (default: 80)
  -l LISTEN_HOST, --listen-host LISTEN_HOST
                        listen host (default: 127.0.0.1)
  -P LISTEN_PORT, --listen-port LISTEN_PORT
                        listen port (default: 8080)
  -i INJECT_HOST, --inject-host INJECT_HOST
                        inject host (default: None)
  -r, --prepend-inject-host
                        prepend injected host instead of append (default: False)
  -o OVERRIDE_HOST, --override-host OVERRIDE_HOST
                        override request host (default: None)
  -X, --drop-x-headers  drop X-* headers (default: False)
  -v, --verbose         verbose logging (default: False)
```