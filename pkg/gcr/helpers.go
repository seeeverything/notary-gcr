package gcr

import (
	// "github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/client"
)

// clearChangelist clears the notary staging changelist.
func clearChangeList(notaryRepo client.Repository) error {
	cl, err := notaryRepo.GetChangelist()
	if err != nil {
		return err
	}
	return cl.Clear("")
}
