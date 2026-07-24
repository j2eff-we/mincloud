BINARY := mincloud
IMAGE  := mincloud

.PHONY: build test e2e run docker docker-run clean

build:
	go build -o $(BINARY) ./cmd/mincloud

test:
	go test ./...

e2e:
	bash scripts/e2e.sh

run: build
	./$(BINARY)

docker:
	docker build -t $(IMAGE) .

docker-run: docker
	docker run --rm -p 9900:9900 -p 9910:9910 -p 9920:9920 $(IMAGE)

clean:
	rm -f $(BINARY)
