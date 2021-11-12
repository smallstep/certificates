package sshagentkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/smallstep/certificates/kms/apiv1"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"go.step.sm/crypto/pemutil"
)

// Some helpers with inspiration from crypto/ssh/agent/client_test.go

// startOpenSSHAgent executes ssh-agent, and returns an Agent interface to it.
func startOpenSSHAgent(t *testing.T) (client agent.Agent, socket string, cleanup func()) {
	/* Always test with OpenSSHAgent
	if testing.Short() {
		// ssh-agent is not always available, and the key
		// types supported vary by platform.
		t.Skip("skipping test due to -short")
	}
	*/

	bin, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("could not find ssh-agent")
	}

	cmd := exec.Command(bin, "-s")
	cmd.Env = []string{} // Do not let the user's environment influence ssh-agent behavior.
	cmd.Stderr = new(bytes.Buffer)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
	}

	// Output looks like:
	//
	//	SSH_AUTH_SOCK=/tmp/ssh-P65gpcqArqvH/agent.15541; export SSH_AUTH_SOCK;
	//	SSH_AGENT_PID=15542; export SSH_AGENT_PID;
	//	echo Agent pid 15542;

	fields := bytes.Split(out, []byte(";"))
	line := bytes.SplitN(fields[0], []byte("="), 2)
	line[0] = bytes.TrimLeft(line[0], "\n")
	if string(line[0]) != "SSH_AUTH_SOCK" {
		t.Fatalf("could not find key SSH_AUTH_SOCK in %q", fields[0])
	}
	socket = string(line[1])

	line = bytes.SplitN(fields[2], []byte("="), 2)
	line[0] = bytes.TrimLeft(line[0], "\n")
	if string(line[0]) != "SSH_AGENT_PID" {
		t.Fatalf("could not find key SSH_AGENT_PID in %q", fields[2])
	}
	pidStr := line[1]
	pid, err := strconv.Atoi(string(pidStr))
	if err != nil {
		t.Fatalf("Atoi(%q): %v", pidStr, err)
	}

	conn, err := net.Dial("unix", string(socket))
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}

	ac := agent.NewClient(conn)
	return ac, socket, func() {
		proc, _ := os.FindProcess(pid)
		if proc != nil {
			proc.Kill()
		}
		conn.Close()
		os.RemoveAll(filepath.Dir(socket))
	}
}

func startAgent(t *testing.T, sshagent agent.Agent) (client agent.Agent, cleanup func()) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	go agent.ServeAgent(sshagent, c2)

	return agent.NewClient(c1), func() {
		c1.Close()
		c2.Close()
	}
}

// startKeyringAgent uses Keyring to simulate a ssh-agent Server and returns a client.
func startKeyringAgent(t *testing.T) (client agent.Agent, cleanup func()) {
	return startAgent(t, agent.NewKeyring())
}

type startTestAgentFunc func(t *testing.T, keysToAdd ...agent.AddedKey) (sshagent agent.Agent)

func startTestOpenSSHAgent(t *testing.T, keysToAdd ...agent.AddedKey) (sshagent agent.Agent) {
	sshagent, _, cleanup := startOpenSSHAgent(t)
	for _, keyToAdd := range keysToAdd {
		err := sshagent.Add(keyToAdd)
		if err != nil {
			t.Fatalf("sshagent.add: %v", err)
		}
	}
	t.Cleanup(cleanup)

	//testAgentInterface(t, sshagent, key, cert, lifetimeSecs)
	return sshagent
}

func startTestKeyringAgent(t *testing.T, keysToAdd ...agent.AddedKey) (sshagent agent.Agent) {
	sshagent, cleanup := startKeyringAgent(t)
	for _, keyToAdd := range keysToAdd {
		err := sshagent.Add(keyToAdd)
		if err != nil {
			t.Fatalf("sshagent.add: %v", err)
		}
	}
	t.Cleanup(cleanup)

	//testAgentInterface(t, agent, key, cert, lifetimeSecs)
	return sshagent
}

// netPipe is analogous to net.Pipe, but it uses a real net.Conn, and
// therefore is buffered (net.Pipe deadlocks if both sides start with
// a write.)
func netPipe() (net.Conn, net.Conn, error) {
	listener, err := netListener()
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	c1, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	c2, err := listener.Accept()
	if err != nil {
		c1.Close()
		return nil, nil, err
	}

	return c1, c2, nil
}

// netListener creates a localhost network listener.
func netListener() (net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener, err = net.Listen("tcp", "[::1]:0")
		if err != nil {
			return nil, err
		}
	}
	return listener, nil
}

func TestNew(t *testing.T) {
	comment := "Key from OpenSSHAgent"
	// Ensure we don't "inherit" any SSH_AUTH_SOCK
	os.Unsetenv("SSH_AUTH_SOCK")

	sshagent, socket, cleanup := startOpenSSHAgent(t)

	os.Setenv("SSH_AUTH_SOCK", socket)
	t.Cleanup(func() {
		os.Unsetenv("SSH_AUTH_SOCK")
		cleanup()
	})

	// Test that we can't find any signers in the agent before we have loaded them
	t.Run("No keys with OpenSSHAgent", func(t *testing.T) {
		kms, err := New(context.Background(), apiv1.Options{})
		if kms == nil || err != nil {
			t.Errorf("New() = %v, %v", kms, err)
		}
		signer, err := kms.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:" + comment})
		if err == nil || signer != nil {
			t.Errorf("SSHAgentKMS.CreateSigner() error = \"%v\", signer = \"%v\"", err, signer)
		}
	})

	// Load ssh test fixtures
	b, err := os.ReadFile("testdata/ssh")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}

	// And add that key to the agent
	err = sshagent.Add(agent.AddedKey{PrivateKey: privateKey, Comment: comment})
	if err != nil {
		t.Fatalf("sshagent.add: %v", err)
	}

	// And test that we can find it when it's loaded
	t.Run("Keys with OpenSSHAgent", func(t *testing.T) {
		kms, err := New(context.Background(), apiv1.Options{})
		if kms == nil || err != nil {
			t.Errorf("New() = %v, %v", kms, err)
		}
		signer, err := kms.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:" + comment})
		if err != nil || signer == nil {
			t.Errorf("SSHAgentKMS.CreateSigner() error = \"%v\", signer = \"%v\"", err, signer)
		}
	})
}

func TestNewFromAgent(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name            string
		args            args
		sshagentstarter startTestAgentFunc
		wantErr         bool
	}{
		{"ok OpenSSHAgent", args{context.Background(), apiv1.Options{}}, startTestOpenSSHAgent, false},
		{"ok KeyringAgent", args{context.Background(), apiv1.Options{}}, startTestKeyringAgent, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFromAgent(tt.args.ctx, tt.args.opts, tt.sshagentstarter(t))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("NewFromAgent() = %v", got)
			}
		})
	}
}

func TestSSHAgentKMS_Close(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ok", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHAgentKMS{}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("SSHAgentKMS.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSSHAgentKMS_CreateSigner(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := pemutil.Serialize(pk)
	if err != nil {
		t.Fatal(err)
	}
	pemBlockPassword, err := pemutil.Serialize(pk, pemutil.WithPassword([]byte("pass")))
	if err != nil {
		t.Fatal(err)
	}

	// Read and decode file using standard packages
	b, err := os.ReadFile("testdata/priv.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	block.Bytes, err = x509.DecryptPEMBlock(block, []byte("pass")) //nolint
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create a public PEM
	b, err = x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	// Load ssh test fixtures
	sshPubKeyStr, err := os.ReadFile("testdata/ssh.pub")
	if err != nil {
		t.Fatal(err)
	}
	_, comment, _, _, err := ssh.ParseAuthorizedKey(sshPubKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/ssh")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	sshPrivateKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wrappedSSHPrivateKey := NewWrappedSignerFromSSHSigner(sshPrivateKey)

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"signer", args{&apiv1.CreateSignerRequest{Signer: pk}}, pk, false},
		{"pem", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pem.EncodeToMemory(pemBlock)}}, pk, false},
		{"pem password", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pem.EncodeToMemory(pemBlockPassword), Password: []byte("pass")}}, pk, false},
		{"file", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/priv.pem", Password: []byte("pass")}}, pk2, false},
		{"sshagent", args{&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:" + comment}}, wrappedSSHPrivateKey, false},
		{"sshagent Nonexistant", args{&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:Nonexistant"}}, nil, true},
		{"fail", args{&apiv1.CreateSignerRequest{}}, nil, true},
		{"fail bad pem", args{&apiv1.CreateSignerRequest{SigningKeyPEM: []byte("bad pem")}}, nil, true},
		{"fail bad password", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/priv.pem", Password: []byte("bad-pass")}}, nil, true},
		{"fail not a signer", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pub}}, nil, true},
		{"fail not a signer from file", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/pub.pem"}}, nil, true},
		{"fail missing", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/missing"}}, nil, true},
	}
	starters := []struct {
		name    string
		starter startTestAgentFunc
	}{
		{"startTestOpenSSHAgent", startTestOpenSSHAgent},
		{"startTestKeyringAgent", startTestKeyringAgent},
	}
	for _, starter := range starters {
		k, err := NewFromAgent(context.Background(), apiv1.Options{}, starter.starter(t, agent.AddedKey{PrivateKey: privateKey, Comment: comment}))
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range tests {
			t.Run(starter.name+"/"+tt.name, func(t *testing.T) {
				got, err := k.CreateSigner(tt.args.req)
				if (err != nil) != tt.wantErr {
					t.Errorf("SSHAgentKMS.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				// nolint:gocritic
				switch s := got.(type) {
				case *WrappedSSHSigner:
					gotPkS := s.Sshsigner.PublicKey().(*agent.Key).String() + "\n"
					wantPkS := string(sshPubKeyStr)
					if !reflect.DeepEqual(gotPkS, wantPkS) {
						t.Errorf("SSHAgentKMS.CreateSigner() = %T, want %T", gotPkS, wantPkS)
						t.Errorf("SSHAgentKMS.CreateSigner() = %v, want %v", gotPkS, wantPkS)
					}
				default:
					if !reflect.DeepEqual(got, tt.want) {
						t.Errorf("SSHAgentKMS.CreateSigner() = %T, want %T", got, tt.want)
						t.Errorf("SSHAgentKMS.CreateSigner() = %v, want %v", got, tt.want)
					}
				}
			})
		}
	}
}

/*
func restoreGenerateKey() func() {
	oldGenerateKey := generateKey
	return func() {
		generateKey = oldGenerateKey
	}
}
*/

/*
func TestSSHAgentKMS_CreateKey(t *testing.T) {
	fn := restoreGenerateKey()
	defer fn()

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edpub, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		req *apiv1.CreateKeyRequest
	}
	type params struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name        string
		args        args
		generateKey func() (interface{}, interface{}, error)
		want        *apiv1.CreateKeyResponse
		wantParams  params
		wantErr     bool
	}{
		{"p256", args{&apiv1.CreateKeyRequest{Name: "p256", SignatureAlgorithm: apiv1.ECDSAWithSHA256}}, func() (interface{}, interface{}, error) {
			return p256.Public(), p256, nil
		}, &apiv1.CreateKeyResponse{Name: "p256", PublicKey: p256.Public(), PrivateKey: p256, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: p256}}, params{"EC", "P-256", 0}, false},
		{"rsa", args{&apiv1.CreateKeyRequest{Name: "rsa3072", SignatureAlgorithm: apiv1.SHA256WithRSA}}, func() (interface{}, interface{}, error) {
			return rsa2048.Public(), rsa2048, nil
		}, &apiv1.CreateKeyResponse{Name: "rsa3072", PublicKey: rsa2048.Public(), PrivateKey: rsa2048, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: rsa2048}}, params{"RSA", "", 0}, false},
		{"rsa2048", args{&apiv1.CreateKeyRequest{Name: "rsa2048", SignatureAlgorithm: apiv1.SHA256WithRSA, Bits: 2048}}, func() (interface{}, interface{}, error) {
			return rsa2048.Public(), rsa2048, nil
		}, &apiv1.CreateKeyResponse{Name: "rsa2048", PublicKey: rsa2048.Public(), PrivateKey: rsa2048, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: rsa2048}}, params{"RSA", "", 2048}, false},
		{"rsaPSS2048", args{&apiv1.CreateKeyRequest{Name: "rsa2048", SignatureAlgorithm: apiv1.SHA256WithRSAPSS, Bits: 2048}}, func() (interface{}, interface{}, error) {
			return rsa2048.Public(), rsa2048, nil
		}, &apiv1.CreateKeyResponse{Name: "rsa2048", PublicKey: rsa2048.Public(), PrivateKey: rsa2048, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: rsa2048}}, params{"RSA", "", 2048}, false},
		{"ed25519", args{&apiv1.CreateKeyRequest{Name: "ed25519", SignatureAlgorithm: apiv1.PureEd25519}}, func() (interface{}, interface{}, error) {
			return edpub, edpriv, nil
		}, &apiv1.CreateKeyResponse{Name: "ed25519", PublicKey: edpub, PrivateKey: edpriv, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: edpriv}}, params{"OKP", "Ed25519", 0}, false},
		{"default", args{&apiv1.CreateKeyRequest{Name: "default"}}, func() (interface{}, interface{}, error) {
			return p256.Public(), p256, nil
		}, &apiv1.CreateKeyResponse{Name: "default", PublicKey: p256.Public(), PrivateKey: p256, CreateSignerRequest: apiv1.CreateSignerRequest{Signer: p256}}, params{"EC", "P-256", 0}, false},
		{"fail algorithm", args{&apiv1.CreateKeyRequest{Name: "fail", SignatureAlgorithm: apiv1.SignatureAlgorithm(100)}}, func() (interface{}, interface{}, error) {
			return p256.Public(), p256, nil
		}, nil, params{}, true},
		{"fail generate key", args{&apiv1.CreateKeyRequest{Name: "fail", SignatureAlgorithm: apiv1.ECDSAWithSHA256}}, func() (interface{}, interface{}, error) {
			return nil, nil, fmt.Errorf("an error")
		}, nil, params{"EC", "P-256", 0}, true},
		{"fail no signer", args{&apiv1.CreateKeyRequest{Name: "fail", SignatureAlgorithm: apiv1.ECDSAWithSHA256}}, func() (interface{}, interface{}, error) {
			return 1, 2, nil
		}, nil, params{"EC", "P-256", 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHAgentKMS{}
			generateKey = func(kty, crv string, size int) (interface{}, interface{}, error) {
				if tt.wantParams.kty != kty {
					t.Errorf("GenerateKey() kty = %s, want %s", kty, tt.wantParams.kty)
				}
				if tt.wantParams.crv != crv {
					t.Errorf("GenerateKey() crv = %s, want %s", crv, tt.wantParams.crv)
				}
				if tt.wantParams.size != size {
					t.Errorf("GenerateKey() size = %d, want %d", size, tt.wantParams.size)
				}
				return tt.generateKey()
			}

			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SSHAgentKMS.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SSHAgentKMS.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
*/

func TestSSHAgentKMS_GetPublicKey(t *testing.T) {
	b, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Load ssh test fixtures
	b, err = os.ReadFile("testdata/ssh.pub")
	if err != nil {
		t.Fatal(err)
	}
	sshPubKey, comment, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/ssh")
	if err != nil {
		t.Fatal(err)
	}
	// crypto.PrivateKey
	sshPrivateKey, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"key", args{&apiv1.GetPublicKeyRequest{Name: "testdata/pub.pem"}}, pub, false},
		{"cert", args{&apiv1.GetPublicKeyRequest{Name: "testdata/cert.crt"}}, pub, false},
		{"sshagent", args{&apiv1.GetPublicKeyRequest{Name: "sshagentkms:" + comment}}, sshPubKey, false},
		{"sshagent Nonexistant", args{&apiv1.GetPublicKeyRequest{Name: "sshagentkms:Nonexistant"}}, nil, true},
		{"fail not exists", args{&apiv1.GetPublicKeyRequest{Name: "testdata/missing"}}, nil, true},
		{"fail type", args{&apiv1.GetPublicKeyRequest{Name: "testdata/cert.key"}}, nil, true},
	}
	starters := []struct {
		name    string
		starter startTestAgentFunc
	}{
		{"startTestOpenSSHAgent", startTestOpenSSHAgent},
		{"startTestKeyringAgent", startTestKeyringAgent},
	}
	for _, starter := range starters {
		k, err := NewFromAgent(context.Background(), apiv1.Options{}, starter.starter(t, agent.AddedKey{PrivateKey: sshPrivateKey, Comment: comment}))
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range tests {
			t.Run(starter.name+"/"+tt.name, func(t *testing.T) {
				got, err := k.GetPublicKey(tt.args.req)
				if (err != nil) != tt.wantErr {
					t.Errorf("SSHAgentKMS.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				// nolint:gocritic
				switch tt.want.(type) {
				case ssh.PublicKey:
					// If we want a ssh.PublicKey, protote got to a
					got, err = ssh.NewPublicKey(got)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("SSHAgentKMS.GetPublicKey() = %T, want %T", got, tt.want)
					t.Errorf("SSHAgentKMS.GetPublicKey() = %v, want %v", got, tt.want)
				}
			})
		}
	}
}

func TestSSHAgentKMS_CreateKey(t *testing.T) {
	starters := []struct {
		name    string
		starter startTestAgentFunc
	}{
		{"startTestOpenSSHAgent", startTestOpenSSHAgent},
		{"startTestKeyringAgent", startTestKeyringAgent},
	}
	for _, starter := range starters {
		k, err := NewFromAgent(context.Background(), apiv1.Options{}, starter.starter(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Run(starter.name+"/CreateKey", func(t *testing.T) {
			got, err := k.CreateKey(&apiv1.CreateKeyRequest{
				Name:               "sshagentkms:0",
				SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			})
			if got != nil {
				t.Error("SSHAgentKMS.CreateKey() shoudn't return a value")
			}
			if err == nil {
				t.Error("SSHAgentKMS.CreateKey() didn't return a value")
			}
		})
	}
}
