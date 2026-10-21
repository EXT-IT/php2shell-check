# shellcheck shell=bash
# Sourced by tests/run_tests.sh. HTTP fallback, error reasons, edge blocks.
# shellcheck disable=SC2154  # _t_script and _t_base come from run_tests.sh

_t_run 'refused connection names the reason' 2 'connection refused' bash "$_t_script" -r --no-color "http://127.0.0.1:9/"

if [ -n "${_t_base:-}" ]; then
    _t_hostport=${_t_base#http://}
    # Without a scheme the script tries HTTPS first; the fixture speaks plain
    # HTTP, so the TLS handshake fails and the HTTP fallback must take over.
    _t_run 'URL without scheme falls back to HTTP' 1 'checked over plain HTTP' bash "$_t_script" -r --no-color "$_t_hostport/vulnerable"
    _t_run 'explicit https:// gets no fallback'    2 'no HTTP answer'          bash "$_t_script" -r --no-color "https://$_t_hostport/vulnerable"
    _t_run 'Cloudflare challenge is reported'      0 'block or challenge'      bash "$_t_script" -r --no-color "$_t_base/cf-blocked"
    if bash "$_t_script" -r --no-color "$_t_base/cf-blocked" | grep -q 'OK \] disclosure'; then
        _t_bad 'blocked page is not called clean'
    else
        _t_ok 'blocked page is not called clean'
    fi
else
    echo "  skip  fixture server not available"
fi

if [ -n "${_t_base:-}" ]; then
    # The redirect stays on 127.0.0.1, so the "only the first host" warning
    # cannot fire here; what must hold is that the WAF verdict follows the
    # final hop, which carries no Cloudflare headers.
    if bash "$_t_script" -r --no-color "$_t_base/cf-redirect" | grep -q 'OK \] waf'; then
        _t_bad 'WAF verdict comes from the final hop, not the first'
    else
        _t_ok 'WAF verdict comes from the final hop, not the first'
    fi
fi
