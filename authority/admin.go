package authority

// Admin is the type definining Authority admins. Admins can update Authority
// configuration, provisioners, and even other admins.
type Admin struct {
	ID           string `json:"-"`
	AuthorityID  string `json:"-"`
	Name         string `json:"name"`
	Provisioner  string `json:"provisioner"`
	IsSuperAdmin bool   `json:"isSuperAdmin"`
	IsDeleted    bool   `json:"isDeleted"`
}
