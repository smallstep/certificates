package authority

import "go.step.sm/linkedca"

func (a *Authority) Export() (*linkedca.Configuration, error) {
	var admins []*linkedca.Admin
	var provisioners []*linkedca.Provisioner

	for {
		list, cursor := a.admins.Find("", 100)
		admins = append(admins, list...)
		if cursor == "" {
			break
		}
	}

	for {
		list, cursor := a.provisioners.Find("", 100)
		for _, p := range list {
			lp, err := ProvisionerToLinkedca(p)
			if err != nil {
				return nil, err
			}
			provisioners = append(provisioners, lp)
		}
		if cursor == "" {
			break
		}
	}

	// Global claims for all provisioners.
	claims := claimsToLinkedca(a.config.AuthorityConfig.Claims)

	return &linkedca.Configuration{
		Admins:       admins,
		Provisioners: provisioners,
		Claims:       claims,
	}, nil
}
