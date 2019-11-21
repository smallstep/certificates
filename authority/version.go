package authority

// GlobalVersion stores the version information of the server.
var GlobalVersion = Version{
	Version: "0.0.0",
}

// Version defines the
type Version struct {
	Version                     string
	RequireClientAuthentication bool
}

// Version returns the version information of the server.
func (a *Authority) Version() Version {
	return GlobalVersion
}
