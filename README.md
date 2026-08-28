# spikebench

`spikebench.py` reads a raw HTTP request containing one or more `{{FUZZ}}`
markers and sends a concurrent mutation set to the selected HTTP or HTTPS
origin. The raw request controls the method, target, headers, and body;
`--base` supplies the destination scheme, host, and port.

```text
python spikebench.py request.example.txt --base http://127.0.0.1:8000
```

Use a custom line-oriented payload file when the built-in mutation set is not
appropriate:

```text
python spikebench.py request.example.txt --base https://lab.example --payloads payloads.txt --workers 8 --timeout 5
```

Responses are grouped by status, length, body digest, JSON shape, and redirect
location. Results that diverge from the largest cluster, produce server errors,
change an authorization-style response into success, redirect, fail, or take
unusually long are ranked as outliers. Interesting payloads and nonempty
response bodies are saved under `spikebench_hits` unless `--save` selects a
different directory.

TLS certificate verification is enabled by default. The program uses only the
Python 3 standard library and actively sends network requests, so it should be
used only against systems intended for testing.
