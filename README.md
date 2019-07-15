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

trustedRepo, _ := gcr.NewTrustedGcrRepository(ref, auth)
```
