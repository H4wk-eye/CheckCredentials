# CheckCredentials
## 0x01 What is the CheckCredentials
Some times we need to find out the credentials,so I written this tool and try to find all the credentials in a system.
## 0x02 Usage
```
./checkcredentials -h

When we need to find some secrets in lateralmovement or local check

Usage:
  Checkcredentials [flags]

Flags:
  -f, --format string   Output format (default "text")
  -h, --help            help for Checkcredentials
  -o, --output string   output file (default "result.txt")
  -p, --path string     Path to scan (default:/) (default "/")
  -v, --verbose         More details,default True (default true)
  -w, --workers int     Workers number (default 10)
```
___
## 0x03 TODO
* optimize matching rules
* support more keywords