package webhook

type ControllerOption func(*Controller) error

func WithURL(url string) ControllerOption {
	return func(c *Controller) error {
		c.webhook.URL = url
		return nil
	}
}

func WithBearerToken(token string) ControllerOption {
	return func(c *Controller) error {
		c.webhook.BearerToken = token
		return nil
	}
}

func WithDisableTLSClientAuth(enabled bool) ControllerOption {
	return func(c *Controller) error {
		c.webhook.DisableTLSClientAuth = enabled
		return nil
	}
}
