package secrets

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/k8ssandra/cass-operator/pkg/generated/clientset/versioned/scheme"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var secret = `apiVersion: v1
data:
  ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURlRENDQW1DZ0F3SUJBZ0lSQVBwVm1EV2NtOElNbXlzS2pLQjNuZ0l3RFFZSktvWklodmNOQVFFTEJRQXcKRnpFVk1CTUdBMVVFQXhNTWFXNTBaWEp1YjJSbExXTmhNQjRYRFRJek1EUXhNekEzTURJd00xb1hEVEl6TURjeApNakEzTURJd00xb3dGekVWTUJNR0ExVUVBeE1NYVc1MFpYSnViMlJsTFdOaE1JSUJJakFOQmdrcWhraUc5dzBCCkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTZwMlZKL09xRXh2TEI3a2gvbFpGamF0VWsyVW1kM3hUdUIzOWU3dVgKald1WklaNkE5bTBtUkpTczZiaWEvSXJPU1FwVHhETlRkem9GcTMyOUt6eUVOeVdrbFlnc0VvTFZUUUQxbWZCVAphZkpOZFMvRzA0b0t4U2N5eUNNc0d3MytwSDYzK0NWYkVNUXJkbDNzcDYrbFBIWEhOa09pQXhPN3ZSOWJWTDg1Cnd6V0NyQ0hGL0g3RXIwazFvVVRWQTZYYWJvaitCZTgvbnJDZjlDRHY0MjhRd3VKUEgzclo0TzNtZjBvZmRDMzkKdUYweDJoWDhBUFlGaVVrQmVoS2NLOERWRnFjd3hicm03cDBidmlXakJOM2VhYzVUNjN3NW1CQXVmMmttRzdMQQp0K0s2b0txeWM2cUY5SE9JKzdMaUpqVysrU3k0Q3UxNllsWlIzbEdRTkhKckR3SURBUUFCbzRHK01JRzdNQTRHCkExVWREd0VCL3dRRUF3SUNwREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjBHQTFVZERnUVdCQlRYWExiMVZqUTQKN3BhMEFrQ29iSTJKb1F3TFREQjVCZ05WSFJFRWNqQndnaTlqWVhOekxXOXdaWEpoZEc5eUxYZGxZbWh2YjJzdApjMlZ5ZG1salpTNWpZWE56TFc5d1pYSmhkRzl5TG5OMlk0STlZMkZ6Y3kxdmNHVnlZWFJ2Y2kxM1pXSm9iMjlyCkxYTmxjblpwWTJVdVkyRnpjeTF2Y0dWeVlYUnZjaTV6ZG1NdVkyeDFjM1JsY2k1c2IyTmhiREFOQmdrcWhraUcKOXcwQkFRc0ZBQU9DQVFFQUlkbzF4ZTVUNmFmbUgwNXp4d1c2cWpTcjJEVW84b2pBRkFDbzNSOE9OZTZ0WlFOdApOSHJpRDBmQnJZN3R2L0lFTXY1SmZmaGkzOEhIazJLcy9mVGpnQks5ZWxFdTFNVWExZHA0TDFmK2pVekFZVzhvClRTOGt6TCtLNTd4MndSSy9HcHhXbjlTNzNMZ1VhL1VpK0JpR09abmFsK0FyeEdQSDdLc3kvOTA1Nk52YmdhbWoKMkYyTGxURnhCMFFjNExWQllzN2lBQjQ3WjN2RnByZ0V2MUZDSk9IVnloSXF4NW5wczloRzFEQnZYZGkyZnRiYQpLcFZrcVhvZXhFZWNzdUpyQ2I4U1BZc29KOXJTdGloeE5YZ1FNekNiNWJGa2RLenVCUHBtelZjWDlUZU1rVG9GCmpoUmpIOVNPNzhzY0o3UXB6WUlWYU5aTGFtcFJ2VVdEbGw5ZUtBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURZekNDQWt1Z0F3SUJBZ0lSQU1uNEFhOWVXcHljeEFGaTlnbmxpd1l3RFFZSktvWklodmNOQVFFTEJRQXcKRnpFVk1CTUdBMVVFQXhNTWFXNTBaWEp1YjJSbExXTmhNQjRYRFRJek1EUXhNekEzTURJd04xb1hEVEl6TURjeApNakEzTURJd04xb3dBRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLb3dDM2xwCk9XNVpYYUdLeFZPYTJhRitlM1l6N1k3QTNVbk1ibHNvMUppQmdkemcyUmE4Nm15bktLU1RCd0ZKWkZOMVpHTnoKTzJJUGxTSWRSTTdpbWw0WVk0L0ZvSUpJN1dxL3dmRlZ2Z2RaMjQvWTFyOVVhTDNoUzVHUldFU0l0VzhNRjAxZQppZGtmYWVnYlF0RC9rY3llZWJmL1ZCc01yR2xjc3BnM2pQdWw2ZUpkVzN0QUg1MU5scXdVajV5VFlEcFB1clJMCmFxMnZmdEtsQ1RQWXlyMG9KYkxna3BUYmJlcmZlTGdwYzBQZlQ3UFJ5R2x3QVNCMEJ5c2xDdi9qM2FoejRzYjYKSzFvRmFjaDRTQW01UDhreHI4OUZVL2NUQWRHMFpBMHBGSVFJeFNGSnZMaXFaRDROYlVsWS9wRUNDcmRwOS9CRwpjSUpXS2w0R3Z1K01maDBDQXdFQUFhT0J3RENCdlRBT0JnTlZIUThCQWY4RUJBTUNCYUF3REFZRFZSMFRBUUgvCkJBSXdBREFmQmdOVkhTTUVHREFXZ0JUWFhMYjFWalE0N3BhMEFrQ29iSTJKb1F3TFREQjhCZ05WSFJFQkFmOEUKY2pCd2dpOWpZWE56TFc5d1pYSmhkRzl5TFhkbFltaHZiMnN0YzJWeWRtbGpaUzVqWVhOekxXOXdaWEpoZEc5eQpMbk4yWTRJOVkyRnpjeTF2Y0dWeVlYUnZjaTEzWldKb2IyOXJMWE5sY25acFkyVXVZMkZ6Y3kxdmNHVnlZWFJ2CmNpNXpkbU11WTJ4MWMzUmxjaTVzYjJOaGJEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUEwQ1hyWUdPSlRDamIKT25BWEVhVDBYY3R5YXBDWVBVTjFOTis4Z3g1aXdaT2oxQU5LcUNKTE9leGxEd3BmdkY4dnZnKzB5Z0J3cVd2WApLWlN4UU43ZWlaeGF4SStEV3VmbDNPRk9aOU5ZcEtPZkJuTHVqUDNMNVFTdnpyUDZvUHY3YU9peXRyUDU4Y1k2CkV3ZEZXc0hsZXFQT0s3K2c1bmZwN3NqRVRkZ3lvUEQ2c2QrMWpOY015YnRMeXE5ZmJkd3BNMndnaVRGdEZMSmUKY3ZUejB5TVNtd1JaQVBNQlFmT2ZIMGZ4OVNwMDczcllIb2JPdGlwMXlsUFB0RHhTRGpyY2grQ0pMeXNNQjczMwpia0Q4MW1ZYkFWSE1HM3dKcFlTbm4wK1lrYnkyL24rQm0yVzUvcXZ2bEdjYlZyWXZMZkJDTm5ndFlpck11MkQ0CkFnNGgwYURaSWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  tls.key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRQ3FNQXQ1YVRsdVdWMmgKaXNWVG10bWhmbnQyTSsyT3dOMUp6RzViS05TWWdZSGM0TmtXdk9wc3B5aWtrd2NCU1dSVGRXUmpjenRpRDVVaQpIVVRPNHBwZUdHT1B4YUNDU08xcXY4SHhWYjRIV2R1UDJOYS9WR2k5NFV1UmtWaEVpTFZ2REJkTlhvblpIMm5vCkcwTFEvNUhNbm5tMy8xUWJES3hwWExLWU40ejdwZW5pWFZ0N1FCK2RUWmFzRkkrY2syQTZUN3EwUzJxdHIzN1MKcFFrejJNcTlLQ1d5NEpLVTIyM3EzM2k0S1hORDMwK3owY2hwY0FFZ2RBY3JKUXIvNDkyb2MrTEcraXRhQlduSQplRWdKdVQvSk1hL1BSVlAzRXdIUnRHUU5LUlNFQ01VaFNieTRxbVErRFcxSldQNlJBZ3EzYWZmd1JuQ0NWaXBlCkJyN3ZqSDRkQWdNQkFBRUNnZ0VBU0JIS2VpSzJRR1cxd2RnTFVpbE1LaGh1M2hLRmNpTjRVbTB3K29laTUrWkkKQVNweXBDOWlNcHJqR2padEMvMXhiK3BSbGMvUmdPaEtaa1R3dzQrd2dWSmdyeHlvcVNPSzd0Ni9tWnlPdVh3eQovNHA2L2xFWGZmbHZUL2kxNFdmbk5WeHdiY0l3Sy9NaW5Ua1dKWDFrMTdyd25wdVFtVmZYbDFLN0NyelRoaWorCml3YlZKem9YdWp3TFZqNmxrOUpXYm5VczNZbFhERUJ5b09abjhmN2lwV0tPMElwWmVSWWFuT0doa2ZyTkdhdDMKSkU2cExleFlSTVI2RmZvNm5MM3AwM2Z6ODBEOUErQ0dnbDhPTjVycnJ4RmIxbExoeWpVSE9raTd2bEp1WGlxTApRRXVlWHJYdmlCYjhWWHIwU1VYZEw2TE9Wek9ma2NZWFlLOVdSK3RPZlFLQmdRRGJ1QjZOZ2ZVTUJEY2trOGt5CjFRWlBoT1VJa3AyRkFkTlZ1b252bVpTUVo2WWlIRzlYK24wbWE0cjl4Wk01NERjTWQ5SElHWUIzb3E4OFRUU1EKc01nWnFUOGY2ZUMwOEMwWnd3a2xrL3Jwb0lJZHZueVVtY3FKNE04NlhvdTFzaTQ2Ri9lTkRheXpZOWIxUnJBMAozcHRKd0loUG8zaHhVUjZQSXF6L25qbS8xd0tCZ1FER1NpWUNHVy83clRMWGdONmVvSDhXbGgwR1hGTTFXRUdaCnVBSHRzMmR6QTYva3UxRzZZZGlhdzc1czh1V2lnM0t1U3ZrRjhWK1FSU0ppQUhHOW0vZ1hIT2FqS0hpZ1hkSWcKK0NvYXNqNXkvblQ0VFBUV21YSDIzUTNnMk5uUjBtaHZnT29UVDBNdkZmR3daTS9LUWVrWTI0RUlxbHRzd1FSUApIWllzOGZ4REt3S0JnR0J6YmE0T3kyUlFBV2prR3lGZVZCdmFLYlJlc0Jrd0dQWjhJWXIxYnpzSTFPd0tjWEk4CmVtM0FMYzZDeWNOUlFya05iQ0NiMlVJclB5T0lmTGU3Y3N1WStTWG9SQVVKbmJLK1pDaUQwbFIyYWtmbVU4ZmoKenY1Qm1wWno1SDZKVGpPZ1M4STJxNFpBSUoraFBUNm9MYUR0aktqeENMRXR1KzEzZWx2bnVGQVhBb0dBWkdTVQpPOG5mUGFCaU5tUGowcEpWNWZ5WXMyaTVKREFML3FVQUxQWUJNV1V6Zis0cklkOTZTRmxFcDJxUFF5bWtQWVJ0CjhrbFQ1ZnBxdncyVWlMaFg4blBLZmQ3MnU5TGttWmFyMHBwZUxlQ1JIa253U0ZxbUxhT2I3RFErakJJb21CTy8KNzRqWTdoVUJLaHJRYlluVFY2ZUMrLzBzanJKbTJSdVV0aXJLV3NNQ2dZQkhwaVA2aXFVUlFVZkZRRGVWTkFJNApya2tLMC9NMjdkSWQ5ZVhWRXZ0VUZxSWNwdkpMQXAxNUlIbnNGOFhTTS9IdFFUTlBZdVNCVE9PWXdrV1NEWnpnCnBoVXF6eUk2WGZtWDhUbTdVTUh3QTgvY1JTbUNHMWFWNVNuRG9JcTdtSHBtc00wczV4MG9RSnNBMTJWMDN2Q2EKNmVPVyswQW1nNGhFKzVNTmM3YkFhdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K
kind: Secret
metadata:
  annotations:
    cert-manager.io/alt-names: cass-operator-webhook-service.cass-operator.svc,cass-operator-webhook-service.cass-operator.svc.cluster.local
    cert-manager.io/certificate-name: cass-operator-test-serving-cert
    cert-manager.io/common-name: ""
    cert-manager.io/ip-sans: ""
    cert-manager.io/issuer-group: ""
    cert-manager.io/issuer-kind: Issuer
    cert-manager.io/issuer-name: cass-operator-internode-issuer
    cert-manager.io/uri-sans: ""
    k8ssandra.io/internode-cert: "true"
  creationTimestamp: "2023-04-13T07:02:07Z"
  labels:
    controller.cert-manager.io/fao: "true"
    k8ssandra.io/ssl-cert: "true"
  name: my-test-cert
  namespace: cass-operator
  resourceVersion: "2015"
  uid: 3de31fb6-1bd3-4b54-b7b4-3f5ebdd3a3c6
type: kubernetes.io/tls`

func getSecret() (*corev1.Secret, error) {
	decoder := serializer.NewCodecFactory(scheme.Scheme).UniversalDecoder()
	object := &corev1.Secret{}
	err := runtime.DecodeInto(decoder, []byte(secret), object)
	if err != nil {
		return nil, err
	}
	return object, nil
}

func TestKeyStoreCreation(t *testing.T) {
	require := require.New(t)
	s, err := getSecret()
	require.NoError(err)

	ks, err := createKeyStoreFromSecret(s)
	require.NoError(err)

	ts, err := createTrustStoreFromSecret(s)
	require.NoError(err)

	// TODO Add more checks
	require.True(len(ks.Aliases()) >= 1)
	require.True(len(ts.Aliases()) >= 1)
}

func TestKeyStoreWrite(t *testing.T) {
	require := require.New(t)
	s, err := getSecret()
	require.NoError(err)

	ks, err := createKeyStoreFromSecret(s)
	require.NoError(err)

	ts, err := createTrustStoreFromSecret(s)
	require.NoError(err)

	secret := &corev1.Secret{}
	err = writeKeystoresToSecret(ks, ts, secret)
	require.NoError(err)

	require.NotNil(secret.Data[KeyStoreKey])
	require.NotNil(secret.Data[TrustStoreKey])
}

func TestKeyStoreReadWrite(t *testing.T) {
	require := require.New(t)
	s, err := getSecret()
	require.NoError(err)

	ks, err := createKeyStoreFromSecret(s)
	require.NoError(err)

	ts, err := createTrustStoreFromSecret(s)
	require.NoError(err)

	secret := &corev1.Secret{}
	err = writeKeystoresToSecret(ks, ts, secret)
	require.NoError(err)

	ks2, ts2, err := readKeystoresFromSecret(secret)
	require.NoError(err)

	require.EqualValues(ks.Aliases(), ks2.Aliases())
	require.EqualValues(ts.Aliases(), ts2.Aliases())
}

func TestExpiry(t *testing.T) {
	require := require.New(t)
	s, err := getSecret()
	require.NoError(err)

	ks, err := createKeyStoreFromSecret(s)
	require.NoError(err)

	var validTime time.Time
	for _, k := range ks.Aliases() {
		if ks.IsTrustedCertificateEntry(k) {
			tce, err := ks.GetTrustedCertificateEntry(k)
			require.NoError(err)

			cert, err := x509.ParseCertificate(tce.Certificate.Content)
			require.NoError(err)
			validTime = cert.NotAfter
		}
	}

	startLen := len(ks.Aliases())
	require.True(startLen > 0)

	removeExpired(ks, validTime.Add(-1*time.Minute))
	endLen := len(ks.Aliases())
	require.Equal(startLen, endLen)

	removeExpired(ks, validTime.Add(1*time.Minute))
	endLen = len(ks.Aliases())
	require.True(startLen > endLen)
}
