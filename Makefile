.PHONY: test test-e2e

test:
	go test -v -race ./...

test-e2e:
	docker build -t resurgo-e2e -f e2e/Dockerfile .
	docker run --rm \
		-v $(CURDIR):/workspace \
		-w /workspace \
		resurgo-e2e \
		go test -v -tags e2e ./e2e/...
