package ct

// MultiLog is the interface used to send certificates to multiple logs.
type MultiLog interface {
	GetSCTs(asn1Data ...[]byte) ([]*SCT, error)
	SubmitToLogs(asn1Data ...[]byte) ([]*SCT, error)
}

// MultiLogImpl is the implementation used to send certificates to multiple
// logs.
type MultiLogImpl struct {
	clients []Client
	configs []Config
}

type result struct {
	sct *SCT
	err error
	uri string
}

// NewMultiLog returns a MultiLog with the given configuration.
func NewMultiLog(config []Config) (MultiLog, error) {
	ml := new(MultiLogImpl)
	for _, cfg := range config {
		client, err := New(cfg)
		if err != nil {
			return nil, err
		}
		ml.clients = append(ml.clients, client)
	}
	return ml, nil
}

// GetSCTs submit the precertificate to the logs and returns the list of SCTs to
// embed into the certificate.
func (c *MultiLogImpl) GetSCTs(asn1Data ...[]byte) (scts []*SCT, err error) {
	results := make(chan result, len(c.clients))
	for i := range c.clients {
		client := c.clients[i]
		config := c.configs[i]
		go func() {
			sct, err := client.GetSCTs(asn1Data...)
			results <- result{sct: sct, err: err, uri: config.URI}
		}()
	}

	for i := 0; i < len(c.clients); i++ {
		res := <-results
		switch {
		case res.sct != nil:
			scts = append(scts, res.sct)
		case res.err != nil && err != nil:
			err = res.err
		}
	}

	return scts, err
}

// SubmitToLogs submits the certificate to the certificate transparency logs.
func (c *MultiLogImpl) SubmitToLogs(asn1Data ...[]byte) (scts []*SCT, err error) {
	results := make(chan result, len(c.clients))
	for i := range c.clients {
		client := c.clients[i]
		config := c.configs[i]
		go func() {
			sct, err := client.SubmitToLogs(asn1Data...)
			results <- result{sct: sct, err: err, uri: config.URI}
		}()
	}

	for i := 0; i < len(c.clients); i++ {
		res := <-results
		switch {
		case res.sct != nil:
			scts = append(scts, res.sct)
		case res.err != nil && err != nil:
			err = res.err
		}
	}

	return scts, err
}
