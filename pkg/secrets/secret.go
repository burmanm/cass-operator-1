package secrets

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
)

/*
	For final implementation, also:
		* Do we want a metric that indicates the lifetime left ?
		* Do we wish to create a Kubernetes warning event to indicate something (which we can't renew) is about to expire?
			* Or can we push it to somewhere else? Like Prom alerts? Or just create Alert rule for that metric?


    tls.key: the private key of the certificate.
    tls.crt: the actual certificate.
    ca.crt: the CA bundle that validates the certificate.

*/

// func addToKeyStore(keystore.KeyStore []byte, newPrivateKey []byte) {

// }

const (
	PrivKey       = "tls.key"
	CAKey         = "ca.crt"
	CertKey       = "tls.crt"
	TrustStoreKey = "truststore.jks"
	KeyStoreKey   = "keystore.jks"
)

var password = []byte{'c', 'h', 'a', 'n', 'g', 'e', 'm', 'e'}

// func readKeystoresFromSecret(secret *corev1.Secret) (keystore.KeyStore, keystore.KeyStore) {
// 	/*
// 		Or just compare to existing one?
// 	*/
// }

func createTrustStoreFromSecret(secret *corev1.Secret) (keystore.KeyStore, error) {
	ks := keystore.New()
	b, found := secret.Data[CAKey]
	if !found {
		return ks, fmt.Errorf("unable to find ca.crt from the target secret")
	}

	certs, err := decodeCA(b)
	if err != nil {
		return ks, err
	}

	for i, cert := range certs {
		if err := ks.SetTrustedCertificateEntry(fmt.Sprintf("ts-alias-%d", i), keystore.TrustedCertificateEntry{
			CreationTime: time.Now(), // TODO Should this be in the Secret?
			Certificate: keystore.Certificate{
				Type:    "X509",
				Content: cert.Raw,
			},
		}); err != nil {
			return ks, err
		}
	}

	return ks, nil
}

func createKeyStoreFromSecret(secret *corev1.Secret) (keystore.KeyStore, error) {
	ks := keystore.New()

	b, found := secret.Data[CertKey]
	if !found {
		return ks, fmt.Errorf("unable to find tls.crt from the target secret")
	}

	extractedCerts, err := decodeCA(b)
	if err != nil {
		return ks, err
	}

	certs := make([]keystore.Certificate, 0, len(extractedCerts))
	for _, cert := range extractedCerts {
		certs = append(certs, keystore.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		})
	}

	for i, cert := range certs {
		if err := ks.SetTrustedCertificateEntry(fmt.Sprintf("ks-cert-%d", i), keystore.TrustedCertificateEntry{
			CreationTime: time.Now(), // TODO Should this be in the Secret?
			Certificate:  cert,
		}); err != nil {
			return ks, err
		}
	}

	s, found := secret.Data[PrivKey]
	if !found {
		return ks, fmt.Errorf("unable to find tls.key from the target secret")
	}

	p, _ := pem.Decode(s)
	if p == nil {
		return ks, fmt.Errorf("unable to decode tls.key")
	}

	ks.SetPrivateKeyEntry("private", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(), // TODO Should this be in the Secret?
		PrivateKey:       p.Bytes,
		CertificateChain: certs,
	}, password)

	return ks, nil
}

func tsUpdateNeeded() bool {
	// TODO Compare TrustStores to see if we need to call tsreload on the DSE nodes
	return false
}

func writeKeystoresToSecret(ks keystore.KeyStore, ts keystore.KeyStore, secret *corev1.Secret) error {
	ksBuffer := bytes.Buffer{}
	if err := ks.Store(&ksBuffer, password); err != nil {
		return err
	}

	secret.Data[KeyStoreKey] = ksBuffer.Bytes()

	tsBuffer := bytes.Buffer{}
	if err := ts.Store(&tsBuffer, password); err != nil {
		return err
	}

	secret.Data[TrustStoreKey] = tsBuffer.Bytes()

	return nil
}

func removeExpired(ks keystore.KeyStore, cutTime time.Time) error {
	for _, k := range ks.Aliases() {
		if ks.IsTrustedCertificateEntry(k) {
			tce, err := ks.GetTrustedCertificateEntry(k)
			if err != nil {
				return err
			}

			cert, err := x509.ParseCertificate(tce.Certificate.Content)
			// We allow certificates which are not yet valid - but might be in the future
			if cutTime.After(cert.NotAfter) {
				ks.DeleteEntry(k)
			}
		}
	}

	return nil
}

func updateKeystoreInSecret(input, output *corev1.Secret) {
	// Read existing JKS files from output (if they exist)
	// Read new ones from input, go through the output - remove expired ones, add new ones in
}

// trustStore needs the ca.crt
// readKeystoreFromSecret, writeKeystoreToSecret ? Same for TrustStores

func decodeCA(ca []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	for p, rest := pem.Decode(ca); p != nil; p, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}

		if time.Now().After(cert.NotAfter) {
			return nil, fmt.Errorf("certificate validity has expired")
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
