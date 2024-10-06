# Auth service for ingress-nginx PoC

## Option 1: Manual deployment

### Requirements

* [kind](https://kind.sigs.k8s.io/)
* kubectl
* Helm
* Docker

### Installation

```bash
# Start cluster
kind create cluster --config kind-cluster.yaml

# Add ingress controller helm repo if not already added
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx

# Install ingress controller. We'll use NodePort so we don't need to run cloud-provider-kind
helm install -n ingress-nginx --create-namespace \
    ingress-nginx ingress-nginx/ingress-nginx \
    --set controller.hostPort.enabled=true \
    --set controller.service.type=NodePort \
    --set controller.watchIngressWithoutClass=true \
    --set controller.extraArgs.publish-status-address=localhost \
    --set controller.publishService.enabled=false

# Get docker host IP from kind network, it will be used as client IP in the ingress controller
docker inspect kind-control-plane  -f '{{.NetworkSettings.Networks.kind.Gateway}}'

# Update acl.yaml with previously obtained local docker host address
vim manifests/auth-service/acl.yaml

# Build app image, load into kind
docker build -t auth-svc:1.0 apps/auth-svc
kind load docker-image auth-svc:1.0

# Install manifests
kubectl apply -k manifests
```

### Development process

1. modify app sources => `docker build -t auth-svc:1.0 apps/auth-svc` => `kind load docker-image auth-svc:1.0` => `kubectl -n example rollout restart deployment auth-service`
2. modify manifests or acl.yaml => `kubectl apply -k manifests`

### Teardown

```bash
tilt down
docker stop kind-control-plane
docker rm kind-control-plane
```

## Option 2: Use Tilt

### Requirements

* [kind](https://kind.sigs.k8s.io/)
* kubectl
* Helm
* Docker
* [Tilt](https://docs.tilt.dev/install.html)
* [ctlptl](https://github.com/tilt-dev/ctlptl)

### Installation

```bash
# Create Cluster with registry
ctlptl create cluster kind --registry=ctlptl-registry

# Get docker host IP from kind network, it will be used as client IP in the ingress controller
docker inspect kind-control-plane  -f '{{.NetworkSettings.Networks.kind.Gateway}}'

# Update acl.yaml with previously obtained local docker host address
vim manifests/auth-service/acl.yaml

# Spin up tilt stack
tilt up
```

### Development process

1. modify app sources => live image update, no action is needed
2. modify manifests or acl.yaml => manifests are updated autmatically, no action is needed

### Teardown

```bash
tilt down
ctlptl delete cluster tilt
```

## Testing

Protected service running on `http://example.com` is just a plain httpbin image, so the easiest method is
to use cURL for checking the access is allowed or not. Several test users were already
added to [acl.yaml](manifests/auth-service/acl.yaml) file, each pemits access from various
networks.

|User|Token|Permitted networks|
|----|-----|------------------|
|`twoips`|`dHdvaXBzOnRva2VuOnNlY3JldA==`|1.2.3.0/24, 4.5.6.7/32|
|`largeblock`|`bGFyZ2VibG9jazp0b2tlbjpzZWNyZXQ=`|172.16.0.0/12|
|`noaccess`|`bm9hY2Nlc3M6dG9rZW46c2VjcmV0`|None|
|`everywhere`|`ZXZlcnl3aGVyZTp0b2tlbjpzZWNyZXQ=`| Any|
|`dockerhostuser`|`ZG9ja2VyaG9zdHVzZXI6dG9rZW46c2VjcmV0`|172.18.0.1/32|

Example checks:

* Invalid token:

    ```bash
    curl  -H 'host:example.com' -H 'authorization: Bearer invalidtoken'  http://172.18.0.2/headers
    ```

* Unknown user:

    ```bash
    curl  -H 'host:example.com' -H 'authorization: Bearer dW5rbm93bnVzZXI6Yjpj'  http://172.18.0.2/headers
    ```

* Valid user, source IP address not permitted:

    ```bash
    curl  -H 'host:example.com' -H 'authorization: Bearer dHdvaXBzOnRva2VuOnNlY3JldA=='  http://172.18.0.2/headers
    ```

* Valid user, permitted IP address:

    ```bash
    curl  -H 'host:example.com' -H 'authorization: Bearer ZG9ja2VyaG9zdHVzZXI6dG9rZW46c2VjcmV0'  http://172.18.0.2/headers
    ```
