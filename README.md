# Setting authentication with X.509 certificates and mTLS in Authorino

Demo of setting authentication based on X.509 TLS certificates for APIs protected with Authorino. Trusted CAs are stored in Kubernetes `Secret`s labeled for association with the AuthConfig and watched by Authorino.

## Outline

1. Deploy a service called **Talker API**
2. Set up mTLS (Mutual Transport Layer Security) to protect the Talker API (with Envoy and Authorino)
3. Issue intermediate CA certificates to sign client certificates that will be used to authenticate to the API
4. Register the intermediate CAs in Authorino
5. Add an authorization policy to validate the organization presented in the client certificates

The certificate tree will look like the following, where the first and second levels of the tree are respectivelly root and intermediate CAs, and the leaves are the actual client certificates used to authenticate:

![cert-tree](http://www.plantuml.com/plantuml/png/fPB1Zg9048RlF4N5anx01G-RR818Z0TSLyrcl74feICzGhNfRcOoy_JJj1cZRTJ3m0NgBxwlA9WgZL9tRUD9LcgaVSDW4E_I5smEJ4AsoM7uNmWDismKZtSfn8f_iZzXbFhGALO19vZJc_Y8ntsG5kIRew3PAj4MuUEH-zZfMaXE8WYZty4lSuO1yMF0nG1GWJI24ZrdX9mqaoshE6fcz12w_cEdQbQ15f1zys-du1SKFxIworBuH1hzN1hTIACdqecHtiLDRd0JTtCPLpN2i6mu8mqbatha4B7lC5V9vcz1ooHN3RQumwgWTPBD_iqXfp8mDzjaJdjEZ4bEUoksJpg-XQZfeUxLDFIshRKj1LM2BAqF7DYA7yH369c67hROzB2rmWDQLb_tlDE_17ubtibFtMzzFupSqDdm5UZSTDh65UUSsNUxefmZE-gKKTMrpHS0)

For simplicity, the root CA cert will be used to identify the Talker API as a server and to issue the intermediate CA certs that will effectivelly sign the client certs.

## Requirements

- Kubernetes server with [cert-manager](https://github.com/jetstack/cert-manager) running in the cluster
- OpenSSL (to generate X.509 certificates)

Create a containerized Kubernetes server locally using [Kind](https://kind.sigs.k8s.io): ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kind%20create%20cluster%20--name%20authorino-demo))

```sh
kind create cluster --name authorino-demo
```

Install cert-manager in the cluster: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml))

```sh
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.yaml
```

## 1. Deploy the Talker API ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml))

The **Talker API** is just an echo API, included in the Authorino examples. We will use it in this guide as the service to be protected with Authorino.

```sh
kubectl apply -f https://raw.githubusercontent.com/kuadrant/authorino-examples/main/talker-api/talker-api-deploy.yaml
```

## 2. Install Authorino

Install the Authorino Operator: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml))

```sh
kubectl apply -f https://raw.githubusercontent.com/Kuadrant/authorino-operator/main/config/deploy/manifests.yaml
```

Create the TLS certificates for the Authorino service: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$curl%20-sSL%20https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml%20%7C%20sed%20%22s/%5C$(AUTHORINO_INSTANCE)/authorino/g;s/%5C$(NAMESPACE)/default/g%22%20%7C%20kubectl%20apply%20-f%20-))

```sh
curl -sSL https://raw.githubusercontent.com/Kuadrant/authorino/main/deploy/certs.yaml | sed "s/\$(AUTHORINO_INSTANCE)/authorino/g;s/\$(NAMESPACE)/default/g" | kubectl apply -f -
```

Request the Authorino service: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20authorino.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  listener:
    tls:
      certSecretRef:
        name: authorino-server-cert
  oidcServer:
    tls:
      certSecretRef:
        name: authorino-oidc-server-cert
EOF
```

## 3. Create the AuthConfig ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20authconfig.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: authorino.kuadrant.io/v1beta1
kind: AuthConfig
metadata:
  name: talker-api-protection
spec:
  hosts:
  - talker-api-authorino.127.0.0.1.nip.io
  identity:
  - name: mtls
    mtls:
      labelSelectors:
        app: talker-api
  authorization:
  - name: acme
    json:
      rules:
      - selector: auth.identity.Organization
        operator: incl
        value: ACME Inc.
EOF
```

## 4. Create the root CA

Create a working directory and OpenSSL configuration: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$mkdir%20-p%20/tmp/mtls%0Acp%20openssl.cnf%20/tmp/mtls/openssl.cnf%0Aecho%2001%20%3E%20/tmp/mtls/serial%0Atouch%20/tmp/mtls/index.txt))

```sh
mkdir -p /tmp/mtls

cat <<EOF > /tmp/mtls/openssl.cnf
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd
oid_section             = new_oids

[ new_oids ]

[ ca ]
default_ca              = CA_default

[ CA_default ]
dir                     = /tmp/mtls
new_certs_dir           = /tmp/mtls
database                = /tmp/mtls/index.txt
serial                  = /tmp/mtls/serial
certificate             = /tmp/mtls/ca.crt
private_key             = /tmp/mtls/ca.key
default_md              = sha256
policy                  = policy_match

[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits            = 4096
default_md              = sha256
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
x509_extensions         = v3_ca
string_mask             = nombstr

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = ES
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Barcelona
localityName                    = Locality Name (eg, city)
localityName_default            = Barcelona
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = ACME Inc.
organizationalUnitName          = Organizational Unit Name (eg, section)
commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_max                = 64

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

echo 01 > /tmp/mtls/serial
touch /tmp/mtls/index.txt
```

Create the root Certificate Authority (CA) that will sign intermediate CA certs: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$openssl%20req%20-x509%20-sha256%20-days%203650%20-nodes%20-newkey%20rsa:2048%20-config%20/tmp/mtls/openssl.cnf%20-extensions%20v3_ca%20-subj%20%22/CN=talker-api-authorino.127.0.0.1.nip.io%22%20-keyout%20/tmp/mtls/ca.key%20-out%20/tmp/mtls/ca.crt))

```sh
openssl req -x509 -sha256 -days 3650 -nodes -newkey rsa:2048 -config /tmp/mtls/openssl.cnf -extensions v3_ca -subj "/CN=talker-api-authorino.127.0.0.1.nip.io" -keyout /tmp/mtls/ca.key -out /tmp/mtls/ca.crt
```

Store the CA cert in a Kubernetes `Secret` to be used by Envoy: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20create%20secret%20tls%20talker-api-ca%20--cert=/tmp/mtls/ca.crt%20--key=/tmp/mtls/ca.key))

```sh
kubectl create secret tls talker-api-ca --cert=/tmp/mtls/ca.crt --key=/tmp/mtls/ca.key
```

## 5. Setup Envoy ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20apply%20-f%20envoy.yaml))

```sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: envoy
  name: envoy
data:
  envoy.yaml: |
    static_resources:
      listeners:
      - address:
          socket_address:
            address: 0.0.0.0
            port_value: 8000
        filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                - certificate_chain: {filename: "/etc/ssl/certs/talker-api/tls.crt"}
                  private_key: {filename: "/etc/ssl/certs/talker-api/tls.key"}
                validation_context:
                  trusted_ca:
                    filename: /etc/ssl/certs/talker-api/tls.crt
          filters:
          - name: envoy.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: local
              route_config:
                name: local_route
                virtual_hosts:
                - name: local_service
                  domains: ['*']
                  routes:
                  - match: { prefix: / }
                    route: { cluster: talker-api }
              http_filters:
              - name: envoy.filters.http.ext_authz
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                  transport_api_version: V3
                  failure_mode_allow: false
                  include_peer_certificate: true
                  grpc_service:
                    envoy_grpc: { cluster_name: authorino }
                    timeout: 1s
              - name: envoy.filters.http.router
                typed_config: {}
              use_remote_address: true
      clusters:
      - name: authorino
        connect_timeout: 0.25s
        type: strict_dns
        lb_policy: round_robin
        http2_protocol_options: {}
        load_assignment:
          cluster_name: authorino
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: authorino-authorino-authorization
                    port_value: 50051
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
            common_tls_context:
              validation_context:
                trusted_ca:
                  filename: /etc/ssl/certs/authorino-ca-cert.crt
      - name: talker-api
        connect_timeout: 0.25s
        type: strict_dns
        lb_policy: round_robin
        load_assignment:
          cluster_name: talker-api
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: talker-api
                    port_value: 3000
    admin:
      access_log_path: "/tmp/admin_access.log"
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8001
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: envoy
  name: envoy
spec:
  selector:
    matchLabels:
      app: envoy
  template:
    metadata:
      labels:
        app: envoy
    spec:
      containers:
      - args:
        - --config-path /usr/local/etc/envoy/envoy.yaml
        - --service-cluster front-proxy
        - --log-level info
        - --component-log-level filter:trace,http:debug,router:debug
        command:
        - /usr/local/bin/envoy
        image: envoyproxy/envoy:v1.19-latest
        name: envoy
        ports:
        - containerPort: 8000
          name: web
        - containerPort: 8001
          name: admin
        volumeMounts:
        - mountPath: /usr/local/etc/envoy
          name: config
          readOnly: true
        - mountPath: /etc/ssl/certs/authorino-ca-cert.crt
          name: authorino-ca-cert
          readOnly: true
          subPath: ca.crt
        - mountPath: /etc/ssl/certs/talker-api
          name: talker-api-ca
          readOnly: true
      volumes:
      - configMap:
          items:
          - key: envoy.yaml
            path: envoy.yaml
          name: envoy
        name: config
      - name: authorino-ca-cert
        secret:
          defaultMode: 420
          secretName: authorino-ca-cert
      - name: talker-api-ca
        secret:
          defaultMode: 420
          secretName: talker-api-ca
---
apiVersion: v1
kind: Service
metadata:
  name: envoy
spec:
  selector:
    app: envoy
  ports:
  - name: web
    port: 8000
    protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-wildcard-host
spec:
  rules:
  - host: talker-api-authorino.127.0.0.1.nip.io
    http:
      paths:
      - backend:
          service:
            name: envoy
            port: { number: 8000 }
        path: /
        pathType: Prefix
EOF
```

Start tunneling requests from the local host machine to Envoy: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20port-forward%20deployment/envoy%208000:8000%20%26))

```sh
kubectl port-forward deployment/envoy 8000:8000 &
```

# 6. Create the intermediate CAs

Create 3 intermediate CAs: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$openssl%20genrsa%20-out%20/tmp/mtls/intermediate-ca-1.key%202048%0Aopenssl%20req%20-new%20-config%20/tmp/mtls/openssl.cnf%20-key%20/tmp/mtls/intermediate-ca-1.key%20-out%20/tmp/mtls/intermediate-ca-1.csr%20-subj%20%22/CN=intermediate-1%22%0Aopenssl%20ca%20-config%20/tmp/mtls/openssl.cnf%20-in%20/tmp/mtls/intermediate-ca-1.csr%20-out%20/tmp/mtls/intermediate-ca-1.crt%20-extensions%20v3_intermediate_ca%20-days%203650%20-batch%0Aopenssl%20x509%20-in%20/tmp/mtls/intermediate-ca-1.crt%20-out%20/tmp/mtls/intermediate-ca-1.crt%20-outform%20PEM%0A%0Aopenssl%20genrsa%20-out%20/tmp/mtls/intermediate-ca-2.key%202048%0Aopenssl%20req%20-new%20-config%20/tmp/mtls/openssl.cnf%20-key%20/tmp/mtls/intermediate-ca-2.key%20-out%20/tmp/mtls/intermediate-ca-2.csr%20-subj%20%22/CN=intermediate-2%22%0Aopenssl%20ca%20-config%20/tmp/mtls/openssl.cnf%20-in%20/tmp/mtls/intermediate-ca-2.csr%20-out%20/tmp/mtls/intermediate-ca-2.crt%20-extensions%20v3_intermediate_ca%20-days%203650%20-batch%0Aopenssl%20x509%20-in%20/tmp/mtls/intermediate-ca-2.crt%20-out%20/tmp/mtls/intermediate-ca-2.crt%20-outform%20PEM%0A%0Aopenssl%20genrsa%20-out%20/tmp/mtls/intermediate-ca-3.key%202048%0Aopenssl%20req%20-new%20-config%20/tmp/mtls/openssl.cnf%20-key%20/tmp/mtls/intermediate-ca-3.key%20-out%20/tmp/mtls/intermediate-ca-3.csr%20-subj%20%22/CN=intermediate-3%22%0Aopenssl%20ca%20-config%20/tmp/mtls/openssl.cnf%20-in%20/tmp/mtls/intermediate-ca-3.csr%20-out%20/tmp/mtls/intermediate-ca-3.crt%20-extensions%20v3_intermediate_ca%20-days%203650%20-batch%0Aopenssl%20x509%20-in%20/tmp/mtls/intermediate-ca-3.crt%20-out%20/tmp/mtls/intermediate-ca-3.crt%20-outform%20PEM))

```sh
openssl genrsa -out /tmp/mtls/intermediate-ca-1.key 2048
openssl req -new -config /tmp/mtls/openssl.cnf -key /tmp/mtls/intermediate-ca-1.key -out /tmp/mtls/intermediate-ca-1.csr -subj "/CN=intermediate-1"
openssl ca -config /tmp/mtls/openssl.cnf -in /tmp/mtls/intermediate-ca-1.csr -out /tmp/mtls/intermediate-ca-1.crt -extensions v3_intermediate_ca -days 3650 -batch
openssl x509 -in /tmp/mtls/intermediate-ca-1.crt -out /tmp/mtls/intermediate-ca-1.crt -outform PEM

openssl genrsa -out /tmp/mtls/intermediate-ca-2.key 2048
openssl req -new -config /tmp/mtls/openssl.cnf -key /tmp/mtls/intermediate-ca-2.key -out /tmp/mtls/intermediate-ca-2.csr -subj "/CN=intermediate-2"
openssl ca -config /tmp/mtls/openssl.cnf -in /tmp/mtls/intermediate-ca-2.csr -out /tmp/mtls/intermediate-ca-2.crt -extensions v3_intermediate_ca -days 3650 -batch
openssl x509 -in /tmp/mtls/intermediate-ca-2.crt -out /tmp/mtls/intermediate-ca-2.crt -outform PEM

openssl genrsa -out /tmp/mtls/intermediate-ca-3.key 2048
openssl req -new -config /tmp/mtls/openssl.cnf -key /tmp/mtls/intermediate-ca-3.key -out /tmp/mtls/intermediate-ca-3.csr -subj "/CN=intermediate-3"
openssl ca -config /tmp/mtls/openssl.cnf -in /tmp/mtls/intermediate-ca-3.csr -out /tmp/mtls/intermediate-ca-3.crt -extensions v3_intermediate_ca -days 3650 -batch
openssl x509 -in /tmp/mtls/intermediate-ca-3.crt -out /tmp/mtls/intermediate-ca-3.crt -outform PEM
```

Store `intermediate-ca-1` and `intermediate-ca-2` in Kubernetes `Secret`s labeled to be watched by Authorino and associated with the AuthConfig protecting the Talker API: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20create%20secret%20tls%20intermediate-ca-1%20--cert=/tmp/mtls/intermediate-ca-1.crt%20--key=/tmp/mtls/intermediate-ca-1.key%0Akubectl%20label%20secret%20intermediate-ca-1%20authorino.kuadrant.io/managed-by=authorino%20app=talker-api%0A%0Akubectl%20create%20secret%20tls%20intermediate-ca-2%20--cert=/tmp/mtls/intermediate-ca-2.crt%20--key=/tmp/mtls/intermediate-ca-2.key%0Akubectl%20label%20secret%20intermediate-ca-2%20authorino.kuadrant.io/managed-by=authorino%20app=talker-api))

```sh
kubectl create secret tls intermediate-ca-1 --cert=/tmp/mtls/intermediate-ca-1.crt --key=/tmp/mtls/intermediate-ca-1.key
kubectl label secret intermediate-ca-1 authorino.kuadrant.io/managed-by=authorino app=talker-api

kubectl create secret tls intermediate-ca-2 --cert=/tmp/mtls/intermediate-ca-2.crt --key=/tmp/mtls/intermediate-ca-2.key
kubectl label secret intermediate-ca-2 authorino.kuadrant.io/managed-by=authorino app=talker-api
```

Notice that `intermediate-ca-3` was not registered in Authorino as a trusted source of certificates to access the Talker API.

# 7. Generate the client certificates and consume the API

Consume the API as Aisha: ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$openssl%20genrsa%20-out%20/tmp/mtls/aisha.key%202048%0Aopenssl%20req%20-new%20-config%20/tmp/mtls/openssl.cnf%20-key%20/tmp/mtls/aisha.key%20-out%20/tmp/mtls/aisha.csr%20-subj%20%22/CN=aisha/C=PK/L=Islamabad/O=ACME%20Inc./OU=Engineering%22%0Aopenssl%20x509%20-req%20-in%20/tmp/mtls/aisha.csr%20-out%20/tmp/mtls/aisha.crt%20-CA%20/tmp/mtls/intermediate-ca-1.crt%20-CAkey%20/tmp/mtls/intermediate-ca-1.key%20-CAcreateserial%20-days%201%20-sha256%0Acat%20/tmp/mtls/intermediate-ca-1.crt%20%3E%3E%20/tmp/mtls/aisha.crt%0A%0Aclear%0Acurl%20-k%20--cert%20/tmp/mtls/aisha.crt%20--key%20/tmp/mtls/aisha.key%20https://talker-api-authorino.127.0.0.1.nip.io:8000%20-i))

```sh
openssl genrsa -out /tmp/mtls/aisha.key 2048
openssl req -new -config /tmp/mtls/openssl.cnf -key /tmp/mtls/aisha.key -out /tmp/mtls/aisha.csr -subj "/CN=aisha/C=PK/L=Islamabad/O=ACME Inc./OU=Engineering"
openssl x509 -req -in /tmp/mtls/aisha.csr -out /tmp/mtls/aisha.crt -CA /tmp/mtls/intermediate-ca-1.crt -CAkey /tmp/mtls/intermediate-ca-1.key -CAcreateserial -days 1 -sha256
cat /tmp/mtls/intermediate-ca-1.crt >> /tmp/mtls/aisha.crt

curl -k --cert /tmp/mtls/aisha.crt --key /tmp/mtls/aisha.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 200 OK
```

Try to consume the API as John (missing required organization info): ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$openssl%20genrsa%20-out%20/tmp/mtls/john.key%202048%0Aopenssl%20req%20-new%20-config%20/tmp/mtls/openssl.cnf%20-key%20/tmp/mtls/john.key%20-out%20/tmp/mtls/john.csr%20-subj%20%22/CN=john/C=UK/L=London%22%0Aopenssl%20x509%20-req%20-in%20/tmp/mtls/john.csr%20-out%20/tmp/mtls/john.crt%20-CA%20/tmp/mtls/intermediate-ca-2.crt%20-CAkey%20/tmp/mtls/intermediate-ca-2.key%20-CAcreateserial%20-days%201%20-sha256%0Acat%20/tmp/mtls/intermediate-ca-2.crt%20%3E%3E%20/tmp/mtls/john.crt%0A%0Aclear%0Acurl%20-k%20--cert%20/tmp/mtls/john.crt%20--key%20/tmp/mtls/john.key%20https://talker-api-authorino.127.0.0.1.nip.io:8000%20-i))

```sh
openssl genrsa -out /tmp/mtls/john.key 2048
openssl req -new -config /tmp/mtls/openssl.cnf -key /tmp/mtls/john.key -out /tmp/mtls/john.csr -subj "/CN=john/C=UK/L=London"
openssl x509 -req -in /tmp/mtls/john.csr -out /tmp/mtls/john.crt -CA /tmp/mtls/intermediate-ca-2.crt -CAkey /tmp/mtls/intermediate-ca-2.key -CAcreateserial -days 1 -sha256
cat /tmp/mtls/intermediate-ca-2.crt >> /tmp/mtls/john.crt

curl -k --cert /tmp/mtls/john.crt --key /tmp/mtls/john.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 403 Forbidden
# x-ext-auth-reason: Unauthorized
```

Try to consume the API as Niko (client cert issued by non-trusted intermediate CA): ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$openssl%20genrsa%20-out%20/tmp/mtls/niko.key%202048%0Aopenssl%20req%20-new%20-config%20/tmp/mtls/openssl.cnf%20-key%20/tmp/mtls/niko.key%20-out%20/tmp/mtls/niko.csr%20-subj%20%22/CN=niko/C=JP/L=Osaka%22%0Aopenssl%20x509%20-req%20-in%20/tmp/mtls/niko.csr%20-out%20/tmp/mtls/niko.crt%20-CA%20/tmp/mtls/intermediate-ca-3.crt%20-CAkey%20/tmp/mtls/intermediate-ca-3.key%20-CAcreateserial%20-days%201%20-sha256%0Acat%20/tmp/mtls/intermediate-ca-3.crt%20%3E%3E%20/tmp/mtls/niko.crt%0A%0Aclear%0Acurl%20-k%20--cert%20/tmp/mtls/niko.crt%20--key%20/tmp/mtls/niko.key%20https://talker-api-authorino.127.0.0.1.nip.io:8000%20-i))

```sh
openssl genrsa -out /tmp/mtls/niko.key 2048
openssl req -new -config /tmp/mtls/openssl.cnf -key /tmp/mtls/niko.key -out /tmp/mtls/niko.csr -subj "/CN=niko/C=JP/L=Osaka"
openssl x509 -req -in /tmp/mtls/niko.csr -out /tmp/mtls/niko.crt -CA /tmp/mtls/intermediate-ca-3.crt -CAkey /tmp/mtls/intermediate-ca-3.key -CAcreateserial -days 1 -sha256
cat /tmp/mtls/intermediate-ca-3.crt >> /tmp/mtls/niko.crt

curl -k --cert /tmp/mtls/niko.crt --key /tmp/mtls/niko.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="mtls"
# x-ext-auth-reason: x509: certificate signed by unknown authority
```

Notice that Envoy accepts Niko's client certificate as part of a trusted chain. However, the requested is rejected in Authorino.

# 8. Revoke an entire chain of certificates ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kubectl%20delete%20secret/intermediate-ca-2))

```sh
kubectl delete secret/intermediate-ca-2
```

Try to consume the API as John (previously missing required organization info, now access fully revoked at the level of the CA): ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$clear%0Acurl%20-k%20--cert%20/tmp/mtls/john.crt%20--key%20/tmp/mtls/john.key%20https://talker-api-authorino.127.0.0.1.nip.io:8000%20-i))

```sh
curl -k --cert /tmp/mtls/john.crt --key /tmp/mtls/john.key https://talker-api-authorino.127.0.0.1.nip.io:8000 -i
# HTTP/1.1 401 Unauthorized
# www-authenticate: Basic realm="mtls"
# x-ext-auth-reason: x509: certificate signed by unknown authority
```

Notice that Envoy still accepts John's client certificate.

## Cleanup ([▶︎](didact://?commandId=vscode.didact.sendNamedTerminalAString&text=demo$$kind%20delete%20cluster%20--name%20authorino-demo))

```sh
kind delete cluster --name authorino-demo
```
