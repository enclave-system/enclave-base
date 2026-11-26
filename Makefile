# enklave-base build entry points. Run on the Linux build host only.
#
#   make kernel-server go ref ref-test
#
# ENKLAVE_PKI_DIR  PKI directory (pki/enklave-pki init); dev: ~/enklave-pki-dev
# KERNEL_OUT       directory with the kernel debs (outside the repo)

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

ENKLAVE_PKI_DIR ?= $(HOME)/enklave-pki
KERNEL_OUT      ?= $(HOME)/enklave-out
MKOSI           ?= mkosi

KVER        := $(shell tr -d '[:space:]' < kernel/VERSION)
OUT         := $(CURDIR)/out
STAGE       := $(OUT)/stage
REF_VERSION ?= $(shell tr -d '[:space:]' < ref/VERSION)
REF_KERNEL_FLAVOR := server
# Security epoch of this release line: raise it to revoke every older UKI
# (README "Revoking a vulnerable release").
SECURITY_EPOCH ?= $(shell tr -d '[:space:]' < SECURITY_EPOCH)
# State volumes provisioned under an epoch < HEAL_BELOW are rekeyed and wiped
# on the first boot of this release (README "Healing after a compromise").
HEAL_BELOW ?= $(shell tr -d '[:space:]' < HEAL_BELOW)
# Output directories (overridable for variant builds, e.g. other epochs).
REF_OUT      ?= ref
REF_TEST_OUT ?= ref-test
# Development only: allow signing prod images with a DEV-KEYS PKI.
ENKLAVE_DEV_PROD ?= 0

export ENKLAVE_PKI_DIR
# PCR signing public key, plus a self-signed X.509 wrapper of the same key:
# mkosi 27.1 validates SignExpectedPcrCertificate as X.509 (systemd-keyutil),
# while ukify 257 embeds that file as .pcrpkey and needs the PUBLIC KEY block.
ENKLAVE_PCR_CERT := $(OUT)/keys/pcr-signing.pem

kernel_deb = $(KERNEL_OUT)/linux-image-enklave-$(1)_$(KVER)_amd64.deb
# The stable-named deb still carries the versioned dpkg package name.
kernel_pkg = linux-image-$(KVER)-enklave-$(1)

PKI_FILES := sb/db.key sb/db.crt verity/verity.key verity/verity.crt \
             pcr/pcr-signing.key pcr/pcr-signing.pub config/config-signing.pub

.PHONY: kernel-client kernel-server go stage pcr-cert check-pki ref ref-test test-unit test-vm clean

kernel-client: $(call kernel_deb,client)
kernel-server: $(call kernel_deb,server)

# Never rebuilds an existing deb (a full build takes ~25 min); delete it to force.
$(KERNEL_OUT)/linux-image-enklave-%_$(KVER)_amd64.deb:
	kernel/build-kernel.sh $* "$(ENKLAVE_PKI_DIR)" "$(KERNEL_OUT)"

go:
	mkdir -p $(OUT)/bin
	cd go && CGO_ENABLED=0 go build -trimpath -o $(OUT)/bin/ ./cmd/enklave-cfg ./cmd/enklave-selftest ./cmd/enklave-varauth ./cmd/enklave-sign-policy

check-pki:
	@for f in $(PKI_FILES); do \
	    [ -f "$(ENKLAVE_PKI_DIR)/$$f" ] || { echo "missing $(ENKLAVE_PKI_DIR)/$$f (set ENKLAVE_PKI_DIR)" >&2; exit 1; }; \
	done

# Binaries and public keys that go into the image (/usr).
stage: go check-pki
	rm -rf $(STAGE)
	install -D -m 0755 $(OUT)/bin/enklave-cfg $(STAGE)/usr/lib/enklave/enklave-cfg
	install -D -m 0755 $(OUT)/bin/enklave-selftest $(STAGE)/usr/lib/enklave/enklave-selftest
	install -D -m 0755 $(OUT)/bin/enklave-varauth $(STAGE)/usr/lib/enklave/enklave-varauth
	install -D -m 0644 $(ENKLAVE_PKI_DIR)/config/config-signing.pub $(STAGE)/usr/share/enklave/keys/config-signing.pub
	printf '{"epoch":%d,"heal_below":%d}\n' $(SECURITY_EPOCH) $(HEAL_BELOW) > $(STAGE)/usr/lib/enklave/release.json

pcr-cert: check-pki
	mkdir -p $(dir $(ENKLAVE_PCR_CERT))
	openssl pkey -in $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.key -pubout | cmp -s - $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.pub \
	    || { echo "pcr-signing.pub does not match pcr-signing.key" >&2; exit 1; }
	if [ ! -f $(ENKLAVE_PCR_CERT) ] || ! sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' $(ENKLAVE_PCR_CERT) \
	        | cmp -s - $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.pub; then \
	    { cat $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.pub; \
	      openssl req -new -x509 -key $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.key \
	          -subj "/CN=enklave PCR policy signing/O=enklave" -days 3650 -sha256; \
	    } > $(ENKLAVE_PCR_CERT).tmp; \
	    mv $(ENKLAVE_PCR_CERT).tmp $(ENKLAVE_PCR_CERT); \
	fi

# $(1) config dir, $(2) output subdir, $(3) version, $(4) kernel flavor, $(5) extra mkosi args
define mkosi_build
	mkdir -p $(OUT)/$(2) $(OUT)/cache
	$(MKOSI) -C $(1) --force \
	    --output-directory=$(OUT)/$(2) \
	    --cache-directory=$(OUT)/cache \
	    --image-version=$(3) \
	    --package-directory=$(KERNEL_OUT) \
	    --package=$(call kernel_pkg,$(4)) \
	    --extra-tree=$(STAGE) \
	    --secure-boot-key=$(ENKLAVE_PKI_DIR)/sb/db.key \
	    --secure-boot-certificate=$(ENKLAVE_PKI_DIR)/sb/db.crt \
	    --verity-key=$(ENKLAVE_PKI_DIR)/verity/verity.key \
	    --verity-certificate=$(ENKLAVE_PKI_DIR)/verity/verity.crt \
	    --sign-expected-pcr-key=$(ENKLAVE_PKI_DIR)/pcr/pcr-signing.key \
	    --sign-expected-pcr-certificate=$(ENKLAVE_PCR_CERT) \
	    $(5) build
	PATH="$$PATH:/usr/sbin:/sbin" $(OUT)/bin/enklave-sign-policy \
	    --uki $(OUT)/$(2)/enklave-$(1)_$(3).efi \
	    --key $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.key --pub $(ENKLAVE_PKI_DIR)/pcr/pcr-signing.pub \
	    --epoch $(SECURITY_EPOCH) --role $(1) --profile $(6) --pki $(ENKLAVE_PKI_DIR) \
	    $(if $(filter 1,$(ENKLAVE_DEV_PROD)),--allow-dev-key-for-prod) \
	    --out $(OUT)/$(2)/enklave-$(1)_$(3).policy.json \
	    --image $(OUT)/$(2)/enklave-$(1)_$(3).raw
endef

# $(6) above: profile (prod|test), bound into the TPM policyRef.
ref: kernel-$(REF_KERNEL_FLAVOR) stage pcr-cert
	$(call mkosi_build,ref,$(REF_OUT),$(REF_VERSION),$(REF_KERNEL_FLAVOR),,prod)

ref-test: kernel-$(REF_KERNEL_FLAVOR) stage pcr-cert
	$(call mkosi_build,ref,$(REF_TEST_OUT),$(REF_VERSION),$(REF_KERNEL_FLAVOR),--profile=test,test)

test-unit:
	cd go && go vet ./... && go test ./... -race -count=1
	python3 -m pytest -q -m "not vm" pki/tests kernel/tests

# tests/vm arrives with task 6b; until then only the PKI VM test runs.
test-vm:
	python3 -m pytest -v -m vm pki/tests $(wildcard tests/vm)

clean:
	rm -rf $(OUT)/ref $(OUT)/ref-test $(STAGE) $(OUT)/bin
