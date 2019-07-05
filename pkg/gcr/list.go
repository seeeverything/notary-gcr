package gcr

import (
	"encoding/hex"
	"fmt"

	"github.com/SimonXming/notary-gcr/trust"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
)

func listTargets(ref name.Reference, auth authn.Authenticator, config *trust.Config) ([]*client.Target, error) {
	registry := ref.Context().Registry
	repo, err := trust.GetNotaryRepository(ref, auth, &registry, config)
	if err != nil {
		log.Errorf("failed to get notary repository %s", err)
		return nil, err
	}
	rawTargets, err := repo.ListTargets()
	if err != nil {
		log.Errorf("failed to get notary repository %s", err)
		return nil, err
	}

	var targets []*client.Target
	for _, t := range rawTargets {
		targets = append(targets, &t.Target)
		log.Infof(
			"%s: %s, %s, %s\n",
			t.Name,
			hex.EncodeToString(t.Hashes["sha256"]),
			fmt.Sprintf("%d", t.Length),
			t.Role,
		)
	}
	return targets, nil
}
