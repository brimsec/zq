function await {
  local cmd=$1
  local i=0
  while :; do
    out=$($cmd 2>&1)
    [ $? -eq 0 ] && return
    if ((i++ > 100)); then
      echo "timed out waiting for '$cmd' to succeed -- last output follows"
      echo "$out"
      exit 1
    fi
    sleep 0.1
  done
}

temporal_namespace=zqd-ztest-$RANDOM-$RANDOM
await "tctl --ns $temporal_namespace namespace register"

# With Temporal 1.6.2, a new namespace sometimes isn't visible to
# clients immediately.
sleep 10

mkdir -p data
zqd listen -l=localhost:0 \
  -data=data \
  -loglevel=warn \
  -portfile=zqd.port \
  -temporal.enabled=true \
  -temporal.namespace=$temporal_namespace \
  -temporal.spacecompactdelay=0s \
  -temporal.spacepurgedelay=0s \
  &
trap "kill -9 $! &>/dev/null" EXIT
await '[ -f zqd.port ]'
export ZQD_HOST=localhost:$(cat zqd.port)
