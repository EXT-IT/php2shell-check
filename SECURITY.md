# Security policy

This repository contains a checker, not PHP. Vulnerabilities in PHP itself go
to the PHP project: <https://github.com/php/php-src/security>.

This project has no support and no security contact. It is provided as is,
see the disclaimer in [README.md](README.md#disclaimer). If you find a flaw in
the checker, you may open an issue, but there is no obligation to answer or
fix it.

## Verifying a download

Every release tag has a `SHA256SUMS` file. Check the script against it before
you run it as root:

```sh
sha256sum -c SHA256SUMS
```
