package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

const keylength = 768 // seems to be the minimum we can get away with.

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Powered-By", "Golang!")
	w.Write([]byte("This is an example server.\n"))
	// log.Fprintf(w, "This is an example server.\n")
	// io.WriteString(w, "This is an example server.\n")
}

func main() {
	serverpriv, err := rsa.GenerateKey(rand.Reader, keylength)
	if err != nil {
		log.Println("failed to generate private key: %s", err)
	}

	capriv, err := rsa.GenerateKey(rand.Reader, keylength)
	if err != nil {
		log.Println("failed to generate private key: %s", err)
	}

	log.Printf("Server RSA Private Key: %v", serverpriv)
	log.Printf("CA RSA Private Key: %v", capriv)

	// Dave key to disk
	serverkey, err := os.Create("serverkey.pem")
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
	defer serverkey.Close()

	cakey, err := os.Create("cakey.pem")
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
	defer cakey.Close()
	var capemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(capriv),
	}
	err = pem.Encode(cakey, capemkey)

	var serverprivateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverpriv),
	}

	err = pem.Encode(serverkey, serverprivateKey)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}

	pembytes := pem.EncodeToMemory(serverprivateKey)
	log.Printf("PEM Encoded Private Key: \n%v", string(pembytes))

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Println("failed to generate serial number: %s", err)
	}
	log.Printf("Serial Number of Server Cert is: %v", serialNumber)

	notBefore := time.Now()
	notAfter := notBefore.Add(7 * 24 * time.Hour) // 30 Days proposed

	catemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "My Super Secure CA Server",
			Organization:       []string{"Foo"},
			Country:            []string{"UK"},
			OrganizationalUnit: []string{"Middleware"},
			Locality:           []string{"Cheshire"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // note extra usage
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.MD5WithRSA,
	}
	// With a CA Cert, we have to self-sign.  However, if we can find someone daft enough to sign our CSR who runs a trusted CA,
	// then *boom* - we're now what's known as an intermediate CA.  Most Cert Resellers are intermediate CA's.
	caderBytes, err := x509.CreateCertificate(rand.Reader, &catemplate, &catemplate, publicKey(capriv), capriv)
	if err != nil {
		log.Printf("Failed to create certificate: %s", err)
	}
	cacert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caderBytes})
	err = ioutil.WriteFile("cacert.pem", cacert, 0640)
	if err != nil {
		log.Printf("Error: %v", err)
	}

	log.Printf("CA x509 Certificate: \n%v", string(cacert))

	// Slight Detour - a 'la "Reflections on Trusting Trust" by Ken Thompson (https://www.ece.cmu.edu/~ganger/712.fall02/papers/p761-thompson.pdf)
	// Most (All?) Linux distributions bootstrap their trusted certs from Mozilla.  How?  They download the following file:
	// https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
	//
	// If an attacker (e.g. a state actor) can insert an extra cert, then they have unlimited power to intercept and target your
	// connections.

	servertemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "localhost",
			Organization:       []string{"Foo"},
			Country:            []string{"UK"},
			OrganizationalUnit: []string{"Middleware"},
			Locality:           []string{"Cheshire"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.MD5WithRSA,
	}

	servertemplate.DNSNames = append(servertemplate.DNSNames, "justsomerandomstring")
	servertemplate.DNSNames = append(servertemplate.DNSNames, "localhost")
	servertemplate.EmailAddresses = append(servertemplate.EmailAddresses, "simonb@foo.com")
	servertemplate.IPAddresses = append(servertemplate.IPAddresses, net.ParseIP("127.0.0.1"))
	stringenturl, err := url.Parse("https://localhost:61234/hello")
	servertemplate.URIs = append(servertemplate.URIs, stringenturl)
	//sanlistkey := pem.EncodeToMemory(privateKey)
	//template.DNSNames = append(template.DNSNames, string(sanlistkey))

	// To Self Sign, we use *our* private key to sign the certificate.  With a CA, you're paying them to use their key.
	// I have opinions on this as you'd expect.
	// derBytes, err := x509.CreateCertificate(rand.Reader, &servertemplate, &servertemplate, publicKey(serverpriv), serverpriv)
	// Or, we can sign it with the CA key to get an `proper' cert
	//
	// First, get the cacert loaded
	CACert, err := x509.ParseCertificate(caderBytes)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &servertemplate, CACert, publicKey(serverpriv), capriv)
	if err != nil {
		log.Printf("Failed to create certificate: %s", err)
	}

	pemcert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	err = ioutil.WriteFile("servercert.pem", pemcert, 0640)
	if err != nil {
		log.Printf("Error: %v", err)
	}

	log.Printf("CERT:\n%v", string(pemcert))
	ServerCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}

	for x := range ServerCert.DNSNames {
		log.Printf(ServerCert.DNSNames[x])
	}
	ServerCert.DNSNames = append(ServerCert.DNSNames, "evilhost")
	for x := range ServerCert.DNSNames {
		log.Printf(ServerCert.DNSNames[x])
	}

	// OK, now we've got food, beer and x509 certs.  Let's party.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(pemcert))
	if !ok {
		panic("failed to parse root certificate")
	}
	roots.AddCert(ServerCert)

	subjects := roots.Subjects()
	for x := range subjects {
		log.Printf("%v", string(subjects[x]))
	}

	tlsConfig := &tls.Config{
		// Force it server side
		PreferServerCipherSuites: false,
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}

	httpServer := &http.Server{
		Addr:      "127.0.0.1:61234",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/hello", HelloServer)
	err = httpServer.ListenAndServeTLS("servercert.pem", "serverkey.pem")
	if err != nil {
		log.Printf("ListenAndServe: %v", err)
	}

}
