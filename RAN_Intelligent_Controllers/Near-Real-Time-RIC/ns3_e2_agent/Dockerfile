# ns3-e2-agent image. Derived from NIST's e2-interface e2sim/Dockerfile_kpm
# (e2-interface da6f82f2) and built with the same context (e2-interface/e2sim)
# and registry. Differences from Dockerfile_kpm:
#   - libe2sim is built exactly as there, but the example built on top is
#     e2sm_examples/ns3_e2_agent (this directory) instead of kpm_e2sm;
#   - nlohmann-json comes from the Ubuntu 22.04 package (nlohmann-json3-dev)
#     instead of an unpinned git clone of a third-party repository;
#   - only the build tools are installed (no editors or network tools);
#   - the agent is the ENTRYPOINT (the child of docker-init under
#     `docker run --init`), so the Docker restart policy sees its exits;
#     NIST's image idles on CMD sleep and runs kpm_sim through docker exec.
#   - the metric map is copied to /etc/ns3-e2-agent/;
#   - ric-app-rc's generated E2SM-RC code (pinned commit) builds librc_codec.so;
#   - the agent's copy of NIST's asn1c gets asn1c_patches/ (an X.691 fix of the
#     APER encoder for extension enumeration values, e.g. CauseRICrequest
#     eventTriggerNotSupported); libe2sim stays built from the unpatched tree.
#   - libx2ap_codec.so (the EN-DC X2 SETUP REQUEST of the X2 component's request
#     part) is built from asn1c output of x2ap_codec/asn/x2ap-v19.1.0.asn,
#     generated here by mouse07410/asn1c at a pinned commit (x2ap_codec/SOURCES.txt).
#
# Build (from e2-interface/e2sim, see install_scripts/install_ns3_e2_agent.sh):
#   docker build --build-arg CONTAINER_PULL_REGISTRY=nexus3.o-ran-sc.org:10002 \
#     -f e2sm_examples/ns3_e2_agent/Dockerfile -t ns3-e2-agent:<tag> .
ARG CONTAINER_PULL_REGISTRY=nexus3.o-ran-sc.org:10001
FROM ${CONTAINER_PULL_REGISTRY}/o-ran-sc/bldr-ubuntu22-c-go:1.0.0 AS buildenv

RUN mkdir -p /playpen/e2sim /playpen/agent
WORKDIR /playpen

RUN apt-get update \
	&& apt-get install -y \
	build-essential \
	cmake \
	libsctp-dev \
	lksctp-tools \
	nlohmann-json3-dev \
	git \
	autoconf \
	automake \
	libtool \
	bison \
	flex \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# libe2sim, unmodified, exactly as Dockerfile_kpm builds it.
COPY asn1c/ /playpen/e2sim/asn1c
COPY src/ /playpen/e2sim/src
COPY CMakeLists.txt /playpen/e2sim
RUN mkdir /playpen/e2sim/build && cd /playpen/e2sim/build && cmake .. && make package && cmake .. -DDEV_PKG=1 && make package
RUN dpkg -i /playpen/e2sim/build/e2sim_1.0.0_amd64.deb /playpen/e2sim/build/e2sim-dev_1.0.0_amd64.deb
RUN rm -rf /playpen/e2sim

# ric-app-rc's own generated E2SM-RC v2.0 code, for librc_codec.so (the code
# rc encodes its RIC CONTROL requests with), at the rc commit NIST installs, with
# the Testbed rc patch set (install_patch_files/xApps/rc, copied next to the agent
# by install_ns3_e2_agent.sh) applied in manifest order, as the rc installer does.
ARG RC_SHA=a2282eedc9e32f60298bf530456ad367bef0824b
COPY e2sm_examples/ns3_e2_agent/rc_patches/ /playpen/rc-patches/
RUN git clone -q https://github.com/o-ran-sc/ric-app-rc.git /playpen/rc && git -C /playpen/rc checkout -q $RC_SHA \
	&& test "$(git -C /playpen/rc rev-parse HEAD)" = "$RC_SHA" \
	&& grep -vE '^\s*(#|$)' /playpen/rc-patches/patches.manifest >/tmp/rc-patches.txt && test -s /tmp/rc-patches.txt \
	&& while read -r p; do git -C /playpen/rc apply --whitespace=nowarn "/playpen/rc-patches/$p" || exit 1; done </tmp/rc-patches.txt

# asn1c for the X2AP codec: the commit whose skeleton runtime equals NIST's
# e2sim/asn1c tree (x2ap_codec/SOURCES.txt); the generated C goes to /playpen/x2ap-gen.
ARG ASN1C_SHA=30d7a84e44bb478e360a31202b06045f446e11be
RUN git clone -q https://github.com/mouse07410/asn1c.git /playpen/asn1c-src && git -C /playpen/asn1c-src checkout -q $ASN1C_SHA \
	&& test "$(git -C /playpen/asn1c-src rev-parse HEAD)" = "$ASN1C_SHA" \
	&& cd /playpen/asn1c-src && autoreconf -i && ./configure --prefix=/playpen/asn1c && make -j"$(nproc)" && make install \
	&& rm -rf /playpen/asn1c-src
COPY e2sm_examples/ns3_e2_agent/x2ap_codec/asn/ /playpen/x2ap-asn/
RUN mkdir /playpen/x2ap-gen && cd /playpen/x2ap-gen \
	&& /playpen/asn1c/bin/asn1c -fcompound-names -fno-include-deps -findirect-choice -gen-APER -no-gen-OER \
		-no-gen-example -D . /playpen/x2ap-asn/x2ap-v19.1.0.asn >/playpen/x2ap-asn1c.log 2>&1 \
	&& test -f /playpen/x2ap-gen/X2AP-PDU.c

# The agent, its codec probe and the RC control unit test, against NIST's
# E2AP + E2SM-KPM v3 asn1c (and librc_codec.so for E2SM-RC).
COPY e2sm_examples/ns3_e2_agent/ /playpen/agent/
COPY asn1c/ /playpen/agent/asn1c/
RUN cd /playpen/agent/asn1c && for p in ../asn1c_patches/*.patch; do git apply "$p" || exit 1; done
RUN cd /playpen/agent && rm -rf .build && mkdir .build && cd .build && cmake -DRC_E2SM_DIR=/playpen/rc/e2sm -DX2AP_GEN_DIR=/playpen/x2ap-gen .. \
	&& make -j"$(nproc)" install && ldconfig
RUN mkdir -p /etc/ns3-e2-agent && cp /playpen/agent/schema/metric-map.v1.json /etc/ns3-e2-agent/ \
	&& sha256sum /etc/ns3-e2-agent/metric-map.v1.json
# The image is kept only if the agent's codec and control-path unit tests pass.
RUN mkdir /tmp/codec-probe && codec-probe /etc/ns3-e2-agent/metric-map.v1.json /tmp/codec-probe \
	&& rc-control-test /usr/local/share/ns3-e2-agent/rc-control-requests.hex \
		/usr/local/share/ns3-e2-agent/rc-control-nrcgi.hex \
	&& ue-context-per-seq-test /etc/ns3-e2-agent/metric-map.v1.json && rm -rf /tmp/codec-probe

ENTRYPOINT ["/usr/local/bin/ns3-e2-agent"]
