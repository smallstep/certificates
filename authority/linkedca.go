package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/cli-utils/config"
	"go.step.sm/linkedca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type linkedCaClient struct {
	client      linkedca.MajordomoClient
	authorityID string
}

func createLinkedCAClient(authorityID, endpoint string) (*linkedCaClient, error) {
	base := filepath.Join(config.StepPath(), "linkedca")
	rootFile := filepath.Join(base, "root_ca.crt")
	certFile := filepath.Join(base, "linkedca.crt")
	keyFile := filepath.Join(base, "linkedca.key")

	b, err := ioutil.ReadFile(rootFile)
	if err != nil {
		return nil, errors.Wrap(err, "error reading linkedca root")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.Errorf("error reading %s: no certificates were found", rootFile)
	}

	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrap(err, "error reading linkedca certificate")
			}
			return &cert, nil
		},
	})))
	if err != nil {
		return nil, errors.Wrapf(err, "error connecting %s", endpoint)
	}

	return &linkedCaClient{
		client:      linkedca.NewMajordomoClient(conn),
		authorityID: authorityID,
	}, nil
}

func (c *linkedCaClient) CreateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	resp, err := c.client.CreateProvisioner(ctx, &linkedca.CreateProvisionerRequest{
		Type:         prov.Type,
		Name:         prov.Name,
		Details:      prov.Details,
		Claims:       prov.Claims,
		X509Template: prov.X509Template,
		SshTemplate:  prov.SshTemplate,
	})
	if err != nil {
		return errors.Wrap(err, "error creating provisioner")
	}
	prov.Id = resp.Id
	prov.AuthorityId = resp.AuthorityId
	return nil
}

func (c *linkedCaClient) GetProvisioner(ctx context.Context, id string) (*linkedca.Provisioner, error) {
	resp, err := c.client.GetConfiguration(ctx, &linkedca.ConfigurationRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error getting provisioners")
	}
	for _, p := range resp.Provisioners {
		if p.Id == id {
			return p, nil
		}
	}
	return nil, errs.NotFound("provisioner not found")
}

func (c *linkedCaClient) GetProvisioners(ctx context.Context) ([]*linkedca.Provisioner, error) {
	resp, err := c.client.GetConfiguration(ctx, &linkedca.ConfigurationRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error getting provisioners")
	}
	return resp.Provisioners, nil
}

func (c *linkedCaClient) UpdateProvisioner(ctx context.Context, prov *linkedca.Provisioner) error {
	_, err := c.client.UpdateProvisioner(ctx, &linkedca.UpdateProvisionerRequest{
		Id:           prov.Id,
		Name:         prov.Name,
		Details:      prov.Details,
		Claims:       prov.Claims,
		X509Template: prov.X509Template,
		SshTemplate:  prov.SshTemplate,
	})
	return errors.Wrap(err, "error updating provisioner")
}

func (c *linkedCaClient) DeleteProvisioner(ctx context.Context, id string) error {
	_, err := c.client.DeleteProvisioner(ctx, &linkedca.DeleteProvisionerRequest{
		Id: id,
	})
	return errors.Wrap(err, "error deleting provisioner")
}

func (c *linkedCaClient) CreateAdmin(ctx context.Context, adm *linkedca.Admin) error {
	resp, err := c.client.CreateAdmin(ctx, &linkedca.CreateAdminRequest{
		Subject:       adm.Subject,
		ProvisionerId: adm.ProvisionerId,
		Type:          adm.Type,
	})
	if err != nil {
		return errors.Wrap(err, "error creating admin")
	}
	adm.Id = resp.Id
	adm.AuthorityId = resp.AuthorityId
	return nil
}

func (c *linkedCaClient) GetAdmin(ctx context.Context, id string) (*linkedca.Admin, error) {
	resp, err := c.client.GetConfiguration(ctx, &linkedca.ConfigurationRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error getting admins")
	}
	for _, a := range resp.Admins {
		if a.Id == id {
			return a, nil
		}
	}
	return nil, errs.NotFound("admin not found")
}

func (c *linkedCaClient) GetAdmins(ctx context.Context) ([]*linkedca.Admin, error) {
	resp, err := c.client.GetConfiguration(ctx, &linkedca.ConfigurationRequest{
		AuthorityId: c.authorityID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error getting admins")
	}
	return resp.Admins, nil
}

func (c *linkedCaClient) UpdateAdmin(ctx context.Context, adm *linkedca.Admin) error {
	_, err := c.client.UpdateAdmin(ctx, &linkedca.UpdateAdminRequest{
		Id:   adm.Id,
		Type: adm.Type,
	})
	return errors.Wrap(err, "error updating admin")
}

func (c *linkedCaClient) DeleteAdmin(ctx context.Context, id string) error {
	_, err := c.client.DeleteAdmin(ctx, &linkedca.DeleteAdminRequest{
		Id: id,
	})
	return errors.Wrap(err, "error deleting admin")
}
