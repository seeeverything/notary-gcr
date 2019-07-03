package gcr

import (
	"fmt"
	"encoding/hex"

	"github.com/sirupsen/logrus"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/theupdateframework/notary/client"
	"github.com/SimonXming/notary-gcr/trust"
)

func listTargets(ref name.Reference, auth authn.Authenticator, config *trust.Config) ([]*client.TargetWithRole, error) {
	registry := ref.Context().Registry
	repo, err := trust.GetNotaryRepository(ref, auth, &registry, config)
	if err != nil {
		logrus.Errorf("failed to get notary repository %s", err)
		return nil, err
	}
	logrus.Info("Signing and pushing trust metadata")
	targets, err := repo.ListTargets()
	if err != nil {
		logrus.Errorf("failed to get notary repository %s", err)
		return nil, err
	}
	for _, t := range targets {
		fmt.Println(
			t.Name,
			hex.EncodeToString(t.Hashes["sha256"]),
			fmt.Sprintf("%d", t.Length),
			t.Role,
		)
	}
	return targets, nil
}