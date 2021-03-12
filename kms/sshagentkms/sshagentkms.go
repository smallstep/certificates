package sshagentkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/kms/apiv1"

	"go.step.sm/crypto/pemutil"
)

// SSHAgentKMS is a key manager that uses keys provided by ssh-agent
type SSHAgentKMS struct {
	agentClient agent.Agent
}

// New returns a new SSHAgentKMS.
func New(ctx context.Context, opts apiv1.Options) (*SSHAgentKMS, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open SSH_AUTH_SOCK")
	}

	agentClient := agent.NewClient(conn)

	return &SSHAgentKMS{
		agentClient: agentClient,
	}, nil
}

// NewFromAgent initializes an SSHAgentKMS from a given agent, this method is
// used for testing purposes.
func NewFromAgent(ctx context.Context, opts apiv1.Options, agentClient agent.Agent) (*SSHAgentKMS, error) {
	return &SSHAgentKMS{
		agentClient: agentClient,
	}, nil
}

func init() {
	apiv1.Register(apiv1.SSHAgentKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// Close closes the agent. This is a noop for the SSHAgentKMS.
func (k *SSHAgentKMS) Close() error {
	return nil
}

// WrappedSSHSigner is a utility type to wrap a ssh.Signer as a crypto.Signer
type WrappedSSHSigner struct {
	Sshsigner ssh.Signer
}

// Public returns the agent public key. The type of this public key is
// *agent.Key.
func (s *WrappedSSHSigner) Public() crypto.PublicKey {
	return s.Sshsigner.PublicKey()
}

// Sign signs the given digest using the ssh agent and returns the signature.
func (s *WrappedSSHSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sig, err := s.Sshsigner.Sign(rand, digest)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

// NewWrappedSignerFromSSHSigner returns a new crypto signer wrapping the given
// one.
func NewWrappedSignerFromSSHSigner(signer ssh.Signer) crypto.Signer {
	return &WrappedSSHSigner{signer}
}

func (k *SSHAgentKMS) findKey(signingKey string) (target int, err error) {
	if strings.HasPrefix(signingKey, "sshagentkms:") {
		var key = strings.TrimPrefix(signingKey, "sshagentkms:")

		l, err := k.agentClient.List()
		if err != nil {
			return -1, err
		}
		for i, s := range l {
			if s.Comment == key {
				return i, nil
			}
		}
	}

	return -1, errors.Errorf("SSHAgentKMS couldn't find %s", signingKey)
}

// CreateSigner returns a new signer configured with the given signing key.
func (k *SSHAgentKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.Signer != nil {
		return req.Signer, nil
	}
	if strings.HasPrefix(req.SigningKey, "sshagentkms:") {
		target, err := k.findKey(req.SigningKey)

		if err != nil {
			return nil, err
		}
		s, err := k.agentClient.Signers()
		if err != nil {
			return nil, err
		}
		return NewWrappedSignerFromSSHSigner(s[target]), nil
	}
	// OK: We don't actually care about non-ssh certificates,
	// but we can't disable it in step-ca so this code is copy-pasted from
	// softkms just to keep step-ca happy.
	var opts []pemutil.Options
	if req.Password != nil {
		opts = append(opts, pemutil.WithPassword(req.Password))
	}
	switch {
	case len(req.SigningKeyPEM) != 0:
		v, err := pemutil.ParseKey(req.SigningKeyPEM, opts...)
		if err != nil {
			return nil, err
		}
		sig, ok := v.(crypto.Signer)
		if !ok {
			return nil, errors.New("signingKeyPEM is not a crypto.Signer")
		}
		return sig, nil
	case req.SigningKey != "":
		v, err := pemutil.Read(req.SigningKey, opts...)
		if err != nil {
			return nil, err
		}
		sig, ok := v.(crypto.Signer)
		if !ok {
			return nil, errors.New("signingKey is not a crypto.Signer")
		}
		return sig, nil
	default:
		return nil, errors.New("failed to load softKMS: please define signingKeyPEM or signingKey")
	}
}

// CreateKey generates a new key and returns both public and private key.
func (k *SSHAgentKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return nil, errors.Errorf("SSHAgentKMS doesn't support generating keys")
}

// GetPublicKey returns the public key from the file passed in the request name.
func (k *SSHAgentKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	var v crypto.PublicKey
	if strings.HasPrefix(req.Name, "sshagentkms:") {
		target, err := k.findKey(req.Name)

		if err != nil {
			return nil, err
		}

		s, err := k.agentClient.Signers()
		if err != nil {
			return nil, err
		}

		sshPub := s[target].PublicKey()

		sshPubBytes := sshPub.Marshal()

		parsed, err := ssh.ParsePublicKey(sshPubBytes)
		if err != nil {
			return nil, err
		}

		parsedCryptoKey := parsed.(ssh.CryptoPublicKey)

		// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
		v = parsedCryptoKey.CryptoPublicKey()
	} else {
		var err error
		v, err = pemutil.Read(req.Name)
		if err != nil {
			return nil, err
		}
	}

	switch vv := v.(type) {
	case *x509.Certificate:
		return vv.PublicKey, nil
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return vv, nil
	default:
		return nil, errors.Errorf("unsupported public key type %T", v)
	}
}
