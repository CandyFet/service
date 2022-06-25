SHELL := /bin/bash

# =================================================================
# Building containers

all: sales-api metrics

sales-api:
	docker build \
		-f zarf/docker/Dockerfile.sales-api \
		-t sales-api-amd64:1.0 \
		--build-arg VCS_REF=`git rev-parse HEAD` \
		--build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` \
		.

# =================================================================
# Running from within k8s/dev

kind-up:
	kind create cluster --image kindest/node:v1.19.1 --name service-starter-cluster --config zarf/k8s/dev/kind-config.yaml

kind-down:
	kind delete cluster --name service-starter-cluster

kind-load:
	kind load docker-image sales-api-amd64:1.0 --name service-starter-cluster

kind-services:
	kustomize build zarf/k8s/dev | kubectl apply -f -

kind-sales-api:
	kind laod docker-image sales-api-amd64:1.0 --name service-starter-cluster
	kubectl delete pods -lapp=sales-api

kind-logs:
	kubectl logs -lapp=sales-api --all-containers=true -f

kind-status:
	kubectl get nodes
	kubectl get pods --watch

kind-status-full:
	kubectl describe pod -lapp=sales-api

# =================================================================
run:
	go run app/sales-api/main.go

runa:
	go run app/admin/main.go

test:
	go test -v ./... -count=1
	staticcheck ./...

tidy:
	go mod tidy
	go mod vendor