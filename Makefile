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
# Development only: build the production configuration with a DEV-KEYS PKI.
# Such an image has profile "dev" (its own TPM policyRef), never "prod".
ENKLAVE_DEV_PROD ?= 0
REF_PROFILE := $(if $(filter 1,$(ENKLAVE_DEV_PROD)),dev,prod)
# Per-device admissions (optional, dev and test profiles only): file with one
# TPM endorsement-key Name per line. For each Name the release gets one
# additional signed policy on the ESP that admits exactly that device
# (emulated TPMs of development VMs). Refused for prod: production accepts
# vendor-certified endorsement keys only. See README "TPM authenticity".
EK_ADMIT ?=
# EK certificates fetched from the TPM vendor (optional): directory whose
# files are copied to ESP:/EFI/enklave/ekcert, for TPMs that do not carry
# their certificate in NV (Intel PTT, AMD fTPM). The device verifies them
# against the vendor CAs of the image; nothing here is trusted as such.
EK_CERTS ?=
# 1: only TPMs whose EK certificate is from a firmware-TPM vendor are
# accepted (README "Accepted limits"). Mandatory for role client (refused
# otherwise by enklave-sign-policy, mkosi.finalize and at boot).
REQUIRE_FTPM ?= 0
# Signed Secure Boot variable updates (optional): directory with
# <dbx|db|KEK>-<id>.auth files (scripts/revoke-release.sh) that this release
# applies on its first boot. See README "Revoking a vulnerable release".
EFI_UPDATES ?=
# Public certificates of the CA that certifies the emulated TPMs of the VM
# tests (pki/enklave-pki ek-test-ca); they go into test-profile images only.
EK_TEST_CA ?= $(ENKLAVE_PKI_DIR)/ek-test-ca
STAGE_TEST := $(OUT)/stage-test
DEV_KEYS := $(shell [ -e "$(ENKLAVE_PKI_DIR)/DEV-KEYS" ] && echo true || echo false)

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

.PHONY: kernel-client kernel-server go stage stage-test pcr-cert check-pki ref ref-test test-unit test-vm clean

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
	printf '{"epoch":%d,"heal_below":%d,"dev_keys":%s,"built":%d,"require_ftpm":%s}\n' $(SECURITY_EPOCH) $(HEAL_BELOW) $(DEV_KEYS) "$$(date +%s)" \
	    $(if $(filter 1,$(REQUIRE_FTPM)),true,false) > $(STAGE)/usr/lib/enklave/release.json
	if [ -n "$(EFI_UPDATES)" ]; then \
	    for f in "$(EFI_UPDATES)"/*.auth; do \
	        install -D -m 0644 "$$f" $(STAGE)/usr/lib/enklave/efi-updates/"$$(basename "$$f")"; \
	    done; \
	fi

# Test profile only: the CA of the emulated test TPMs. Refused for a PKI
# without the DEV-KEYS marker: a test CA must never be trusted by a shippable
# image (mkosi.finalize asserts its absence in production images).
stage-test: check-pki
	[ "$(DEV_KEYS)" = true ] || { echo "test images need a DEV-KEYS PKI" >&2; exit 1; }
	rm -rf $(STAGE_TEST)
	for f in issuercert.pem swtpm-localca-rootca-cert.pem; do \
	    [ -f "$(EK_TEST_CA)/$$f" ] || { echo "missing $(EK_TEST_CA)/$$f (run: pki/enklave-pki ek-test-ca $(ENKLAVE_PKI_DIR))" >&2; exit 1; }; \
	    install -D -m 0644 "$(EK_TEST_CA)/$$f" $(STAGE_TEST)/usr/share/enklave/tpm-ek-ca-test/RootCA/"$${f%.pem}.crt"; \
	done

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
	    --release $(STAGE)/usr/lib/enklave/release.json \
	    $(if $(EK_ADMIT),--admit-ek $(EK_ADMIT)) \
	    $(if $(EK_CERTS),--ek-certs $(EK_CERTS)) \
	    --out $(OUT)/$(2)/enklave-$(1)_$(3).policy.json \
	    --image $(OUT)/$(2)/enklave-$(1)_$(3).raw
endef

# $(6) above: profile (prod|test), bound into the TPM policyRef.
ref: kernel-$(REF_KERNEL_FLAVOR) stage pcr-cert
	$(call mkosi_build,ref,$(REF_OUT),$(REF_VERSION),$(REF_KERNEL_FLAVOR),,$(REF_PROFILE))

ref-test: kernel-$(REF_KERNEL_FLAVOR) stage stage-test pcr-cert
	$(call mkosi_build,ref,$(REF_TEST_OUT),$(REF_VERSION),$(REF_KERNEL_FLAVOR),--profile=test --extra-tree=$(STAGE_TEST),test)

test-unit:
	cd go && go vet ./... && go test ./... -race -count=1
	python3 -m pytest -q -m "not vm" pki/tests kernel/tests

# tests/vm arrives with task 6b; until then only the PKI VM test runs.
test-vm:
	python3 -m pytest -v -m vm pki/tests $(wildcard tests/vm)

clean:
	rm -rf $(OUT)/ref $(OUT)/ref-test $(STAGE) $(STAGE_TEST) $(OUT)/bin
