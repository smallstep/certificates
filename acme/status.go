package acme

// Status represents an ACME status.
type Status string

var (
	// StatusValid -- valid
	StatusValid = Status("valid")
	// StatusInvalid -- invalid
	StatusInvalid = Status("invalid")
	// StatusPending -- pending; e.g. an Order that is not ready to be finalized.
	StatusPending = Status("pending")
	// StatusDeactivated -- deactivated; e.g. for an Account that is not longer valid.
	StatusDeactivated = Status("deactivated")
	// StatusReady -- ready; e.g. for an Order that is ready to be finalized.
	StatusReady = Status("ready")
	//statusExpired     = "expired"
	//statusActive      = "active"
	//statusProcessing  = "processing"
)
