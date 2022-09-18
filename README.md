# dpgpid - Decentralized PGP IDentifiers

A world of trust with Decentralized IDentifiers on IPFS.

## Disclaimer

This is work in progress ;)

## Requirements

* gpg
* ipfs
* pinentry
* python3
* python3-pip

## Usage

### dpgpid

dpgpid helps you to publish, retrieve and sign ed25519 keys with decentralized identifiers on IPFS.

* Show identifiers

```shell
$ dpgpid show
```

### keygen

keygen helps you to generate an ed25519 key in different formats

* Show duniter public key for user "username" and password "password"

```shell
$ keygen username password
```

* Show IPFS PeerID and PrivKEY for user "username" and password "password"

```shell
$ keygen -pk -t ipfs username password
```

* Show duniter public and secret keys for GPG key matching uid "username" and protected with password "password"

```shell
$ keygen -pkg username password
```

## Tests

Run tests

```shell
$ make tests
```

## Status

Alpha version, file and output formats may change without retro compatibility.

## References

* [Inter Planetary IDentifiers](https://did-ipid.github.io/ipid-did-method/) did method
