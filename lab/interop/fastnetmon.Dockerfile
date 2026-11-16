# FastNetMon Community 1.2.9 for the interop lane, plus what the bundled
# notify script needs. The official image ships bash, awk, sed, grep and
# flock(1) (util-linux) but not curl, jq or python3; the script requires curl
# and falls back to grep and sed without jq or python3, so only curl is added.
# The attack-details folder is missing from the image, so FastNetMon cannot
# write the per-ban details file it keeps beside the notify call.
FROM ghcr.io/pavel-odintsov/fastnetmon-community:1.2.9@sha256:c154b5b5fd74286719c1c1b97d02157a559926b7749fb5afa958d5faccbd5a0e

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/fastnetmon_attacks
