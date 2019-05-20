#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Require variables.
if [ -z "${NANOBLOG_HTTP_HOST-}" ] ; then
    echo "Environment variable NANOBLOG_HTTP_HOST required. Exiting."
    exit 1
fi

# Allow optional variables.
if [ -z "${NANOBLOG_BACKLINK-}" ] ; then
    export NANOBLOG_BACKLINK=""
fi

if [ -z "${NANOBLOG_LETSENCRYPT-}" ] ; then
    export NANOBLOG_LETSENCRYPT="true"
fi

if [ -z "${SUBSPACE_HTTP_ADDR-}" ] ; then
    export SUBSPACE_HTTP_ADDR=":80"
fi

if [ -z "${SUBSPACE_HTTP_INSECURE-}" ] ; then
    export SUBSPACE_HTTP_INSECURE="false"
fi

# nanoblog service
if ! test -d /etc/sv/nanoblog ; then
    mkdir /etc/sv/nanoblog
    cat <<RUNIT >/etc/sv/nanoblog/run
#!/bin/sh
exec /usr/bin/nanoblog
    "--http-host=${NANOBLOG_HTTP_HOST}" \
    "--http-addr=${NANOBLOG_HTTP_ADDR}" \
    "--http-insecure=${NANOBLOG_HTTP_INSECURE}" \
    "--backlink=${NANOBLOG_BACKLINK}" \
    "--letsencrypt=${NANOBLOG_LETSENCRYPT}"
RUNIT
    chmod +x /etc/sv/nanoblog/run

    # nanoblog service log
    mkdir /etc/sv/nanoblog/log
    mkdir /etc/sv/nanoblog/log/main
    cat <<RUNIT >/etc/sv/nanoblog/log/run
#!/bin/sh
exec svlogd -tt ./main
RUNIT
    chmod +x /etc/sv/nanoblog/log/run
    ln -s /etc/sv/nanoblog /etc/service/nanoblog
fi

exec $@
