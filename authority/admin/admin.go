package admin

// Type specifies the type of administrator privileges the admin has.
type Type string

// Admin type.
type Admin struct {
	ID              string `json:"id"`
	AuthorityID     string `json:"-"`
	Subject         string `json:"subject"`
	ProvisionerName string `json:"provisionerName"`
	ProvisionerType string `json:"provisionerType"`
	ProvisionerID   string `json:"provisionerID"`
	Type            Type   `json:"type"`
}
