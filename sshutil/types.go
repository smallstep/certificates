package sshutil

// HostGroup defines expected attributes for a host group that a host might belong to.
type HostGroup struct {
	ID   string
	Name string
}

// Host defines expected attributes for an ssh host.
type Host struct {
	HostID     string      `json:"hid"`
	HostGroups []HostGroup `json:"host_groups"`
	Hostname   string      `json:"hostname"`
}
