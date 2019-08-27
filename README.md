# notary-gcr
Go library providing high-level Notary API for go-containerregistry.

## Usage

```go
import "github.com/simonshyu/notary-gcr/pkg/gcr"
```


Construct a new Trusted GCR Repository, then use the various action support by the Repository. For example:

```go
auth := &authn.Basic{...}
ref, _ := name.ParseReference("docker-registry.com/foo/image:latest", name.WeakValidation)

trustedRepo, _ := gcr.NewTrustedGcrRepository("~/.notary", ref, auth)
```

## Limitation

Since `google/go-containerregistry` does not support token authentication yet, so if your notary server enable `auth`, this library may not work.
* https://github.com/simonshyu/notary-gcr/issues/6
* https://docs.docker.com/notary/reference/server-config/#auth-section-optional