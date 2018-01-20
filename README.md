[![CircleCI](https://img.shields.io/circleci/project/github/itzg/ezcert.svg)](https://circleci.com/gh/itzg/ezcert)
[![GitHub release](https://img.shields.io/github/release/itzg/ezcert.svg)](https://github.com/itzg/ezcert/releases/latest)

# ezcert user guide

`ezcert` is a tool that focuses on doing one thing, which is generating certificates and keys to enable a
private cluster of servers to securely communicate over an insecure network.

![](docs/PKI%20triad%20of%20trust.png)

## Scenarios

### Setup

By default, the certificate/key files are created in a sub-directory called `certs`, so you will need to create
that directory first, such as

```bash
mkdir certs
```

### Create the CA cert/key

When creating the CA certificate/key, specify a distinguished name (DN) that makes sense for your situation. Since
the default expiration is 30 days, you will likely want to specify a much longer expiration for the CA certificate,
such as:

```bash
ezcert ca --subject "CN=cluster-ca;C=US;L=Dallas;ST=Texas;O=example.com;OU=cluster" --expires 365
```

### Create the Server cert/key

When creating the server certificate/key you need to reference the CA certificate create previously. With server
certificates the hostname(s) are significant since clients will cross-validate the certificate and the intended
server host. The intended hostname should either be the `CN` part of the subject and/or via `--dns` arguments: 

```bash
ezcert server --subject "CN=server.example.com;C=US;L=Dallas;ST=Texas;O=example.com;OU=cluster" \
  --ca-cert certs/ca-cert.pem \ 
  --dns localhost --dns alt-server.example.com
```

### Create the Client cert/keys

Creating the client files is much like the server except that the `CN` is not significant and `--dns` arguments
are not used. The following example shows that the generated file names can be prefixed by using `--prefix`:

```bash
ezcert client --prefix kafka \
  --expires=365 \
  --subject "CN=client;C=US;L=Dallas;ST=Texas;O=example.com;OU=cluster" \
  --ca-cert certs/ca-cert.pem
```

## Usage

```text
usage: ezcert --subject=SUBJECT [<flags>] <command> [<args> ...]

Flags:
  --help             Show context-sensitive help (also try --help-long and --help-man).
  --subject=SUBJECT  A distinguished name (DN) of the certificate's subject, such as CN=widgets.com;C=US;L=Dallas;ST=Texas;O=Internet Widgets;OU=WWW
  --expires=30       Specifies the number of days to make a certificate valid for
  --key-bits=2048    Bit length of the private key to generate
  --out=certs        Existing directory where the certificate and key files will be written
  --log-color        Force color log format
  --version          Show application version.

Commands:
  help [<command>...]
    Show help.

  ca
    Create a CA certificate

  client --ca-cert=CA-CERT [<flags>]
    Create a client certificate from a CA certificate

  server --ca-cert=CA-CERT [<flags>]
    Create a server certificate from a CA certificate
```