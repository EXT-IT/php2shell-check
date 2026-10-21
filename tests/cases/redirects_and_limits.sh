# shellcheck shell=bash
# Sourced by tests/run_tests.sh. Redirect scope, URL cap, address ranges.
# shellcheck disable=SC2154  # _t_script and _t_base come from run_tests.sh

_t_run 'more than 10 URLs is refused'  3 'at most 10 URLs' bash "$_t_script" -r a b c d e f g h i j k
_t_run 'IPv4 range is refused'         3 'address range'   bash "$_t_script" -r 203.0.113.0/24
_t_run 'IPv6 range is refused'         3 'address range'   bash "$_t_script" -r 2001:db8::/32

if [ -n "${_t_base:-}" ]; then
    _t_run 'same-host redirect is followed'   1 'VULN\] php-banner' bash "$_t_script" -r --no-color "$_t_base/redirect-same"
    _t_run 'foreign redirect is not followed' 0 'not followed'      bash "$_t_script" -r --no-color "$_t_base/redirect-foreign"
    _t_count=$(curl -s -D - -o /dev/null "$_t_base/foreign-count" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-count"{print $2}')
    if [ "$_t_count" = 0 ]; then
        _t_ok 'foreign redirect target received no request'
    else
        _t_bad "foreign redirect target received no request (count: ${_t_count:-?})"
    fi
    _t_run 'Cloudflare Access is recognised'  0 'OK \] access'     bash "$_t_script" -r --no-color "$_t_base/redirect-access"
else
    echo "  skip  fixture server not available"
fi
