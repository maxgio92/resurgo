ARCHS ?= amd64 arm64

.PHONY: test test-e2e

define arch_rules
.PHONY: e2e-image-$(1) test-e2e-$(1)

e2e-image-$(1):
	docker build -t resurgo-e2e-$(1) -f e2e/Dockerfile.$(1) .

test-e2e-$(1): e2e-image-$(1)
	docker run --rm \
		-v $$(CURDIR):/src \
		-w /src \
		resurgo-e2e-$(1) \
		go test -v -tags e2e ./e2e/...
endef

$(foreach arch,$(ARCHS),$(eval $(call arch_rules,$(arch))))

test:
	go test -v -race ./...

test-e2e: $(addprefix test-e2e-,$(ARCHS))
