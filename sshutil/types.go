package sshutil

// Hosts are tagged with k,v pairs. These tags are how a user is ultimately
// associated with a host.
type HostTag struct {
	ID    string
	Name  string
	Value string
}

// Host defines expected attributes for an ssh host.
type Host struct {
	HostID   string    `json:"hid"`
	HostTags []HostTag `json:"host_tags"`
	Hostname string    `json:"hostname"`
}
