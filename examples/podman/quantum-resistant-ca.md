## Example [Quantum Resistant CA](https://angrysysadmins.tech/index.php/2022/09/grassyloki/step-ca-change-certificate-authority-and-intermediate-authority-encryption-type-and-key-size/)

Generates:

* **Root CA** with RSA `16384` bit certificate
* **Intermediate CA** with RSA `8192` bit certificate
* Use [higher container limits](https://github.com/smallstep/certificates/tree/master/examples/podman/stepca.container.md): `1` or `2` cores in testing below is ideal
* `PodmanArgs=--memory 50m --cpus 1`

---

* Get a shell in the container & regenerate certificates
* `podman exec -it container_name /bin/bash`

---
```
export root_bits=16384
export intermediate_bits=8192
```

## ROOT CA

```
step certificate create 'My Root CA' \
    $(step path)/certs/root_ca.crt \
    $(step path)/secrets/root_ca_key \
    --profile root-ca \
    --kty RSA --size $root_bits \
    --force
```

8192 bits (root CA generation time)
---
* 1 core = 1 min / 21 secs / 50 secs

16384 bits (root CA generation time)
---
* 8 cores = 3 mins / 12 mins
* 3 cores = 14 mins
* 2 cores = 3 mins / 6 mins / 7 mins / 9 mins / 11 mins / 13 mins
* 1.5 cores = 8 mins / 29 mins
* 1 core = 2 mins / 6 mins / 7.5 mins / 15 mins / 16.5 mins
* 0.5 core = 9 mins / 23 mins

## Intermediate CA

```
step certificate create 'My Intermediate CA' \
    $(step path)/certs/intermediate_ca.crt \
    $(step path)/secrets/intermediate_ca_key \
    --profile intermediate-ca \
    --ca $(step path)/certs/root_ca.crt \
    --ca-key $(step path)/secrets/root_ca_key \
    --kty RSA --size $intermediate_bits \
    --force
```

8192 bits (intermediate CA generation time)
---
* 2 core = 30 secs
* 1 core = 25 secs

---

* Restart the container & note the new X.509 Root Fingerprint: `podman logs container_name` 
* Boostsrap clients

```
port=xxx

step ca bootstrap \
	--ca-url https://ca.mydomain.com:$port \
	--fingerprint 12345678abcdef12345678abcdef12345678abcdef12345678abcdef12345678 \
	--context your_label \
	--force
```

---

* Contributed by: [Stuart Cardall](https://github.com/itoffshore)
