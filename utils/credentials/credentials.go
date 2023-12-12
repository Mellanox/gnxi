/* Copyright 2017 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package credentials loads certificates and validates user credentials.
package credentials

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"reflect"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	log "github.com/golang/glog"
	"github.com/google/gnxi/utils/entity"
)

var (
	ca    = flag.String("ca", "", "CA certificate file.")
	caKey = flag.String("ca_key", "", "CA private key file.")
	cert  = flag.String("cert", "", "Certificate file.")
	key   = flag.String("key", "", "Private key file.")

	// TargetName is a flag containing the hostname verfified by TLS handshake.
	TargetName     = flag.String("target_name", "", "The target name used to verify the hostname returned by TLS handshake")
	insecure       = flag.Bool("insecure", false, "Skip TLS validation.")
	notls          = flag.Bool("notls", false, "Disable TLS validation. If true, no need to specify TLS related options.")
	authorizedUser = userCredentials{}
	usernameKey    = "username"
	passwordKey    = "password"
	caEnt          *entity.Entity
	targetName     = "client.com"
	pin_data       = ""
	ufmCertLocation = "/opt/ufm/files/conf/webclient/ufm_client_authen.db"
)

func init() {
	flag.StringVar(&authorizedUser.username, "username", "", "If specified, uses username/password credentials.")
	flag.StringVar(&authorizedUser.password, "password", "", "The password matching the provided username.")
}

type userCredentials struct {
	username string
	password string
}

func (a *userCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		usernameKey: a.username,
		passwordKey: a.password,
	}, nil
}

func (a *userCredentials) RequireTransportSecurity() bool {
	return true
}

// read the san data from the UFM webclient configuration file.
func read_pin_data() error {
	log.Info("Loading authentication SAN data from webclient.")
	fi, err := ioutil.ReadFile(ufmCertLocation)
	if err != nil {
		//cannot read client ufm client authentication file
		log.Error("Could not read the authentication file at "+ufmCertLocation)
		return fmt.Errorf("Could not read data at:"+ufmCertLocation)
	}
	var result map[string]map[string]interface{}
	err = json.Unmarshal([]byte(fi), &result)
	if err != nil {
		log.Error("Could not read the authentication: " + fmt.Sprint(err))
		return fmt.Errorf("Could not unmarshal the data:" + fmt.Sprint(err))
	}
	if _,found := result["cert_info"]; !found {
		err_str := "Could not find cert_info in the authentication at " + ufmCertLocation
		log.Error(err_str)
		return fmt.Errorf(err_str)
	}
	if _,found := result["cert_info"]["ssl_cert_hostnames"]; !found {
		err_str := "Could not find ssl_cert_hostnames in the authentication at " + ufmCertLocation
		log.Error(err_str)
		return fmt.Errorf(err_str)
	}
	// we convert the file into map of map of interface to extract the string.
	pin_data = fmt.Sprintf("%s", reflect.ValueOf(result["cert_info"]["ssl_cert_hostnames"]).Index(0))
	log.Info("Loaded pin data to server: " + pin_data)
	return nil
}

// Extract the client certification from a known location and compare it to the SAN of the client certificate.
// return nil if cannot open the file or it pass SAN test.
// return error else
func CheckCertSANData(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	log.Info("Starting checking SAN of the client certificate.")
	var certifications []*x509.Certificate
	for _,verifiedChain := range verifiedChains {
		certifications = append(certifications, verifiedChain...)
	}
	if len(verifiedChains) == 0 && len(rawCerts) == 0 {
			return fmt.Errorf("tls: SAN pinning failed, No client certificate found")
	}
	for _,rawCert := range rawCerts {
		data,err := x509.ParseCertificate(rawCert)
		if err != nil {
			log.Warning("Could not parse certification")
			continue
		}
		certifications = append(certifications,data)
	}

	// if we do not have certificate inside of the leaf we need to parse it from the client cert
	for _,certData := range certifications {
		if len(certData.DNSNames) == 0 {
			continue
		}
		log.Info("Found SAN data, got: " + fmt.Sprint(certData.DNSNames))
		for _,SanData := range  certData.DNSNames {
			if SanData != pin_data {
				continue
			}
			// if checked that everything is fine, and we can return true
			return nil
		}
		log.Error("SAN is not equal to authentication file! returning fail connection")
		return fmt.Errorf("tls: SAN pinning failed, client certificate SubjectAltName is incorrect.")
	}
	log.Error("Could not find Client SubjectAltName")
	return fmt.Errorf("tls: SAN pinning failed, client certificate does not have SubjectAltName extension.")
}


// loadFromFile loads a certificate key pair into a tls certificate and a CA certificate into a x509 certificate.
func loadFromFile() (*tls.Certificate, *x509.Certificate) {
	certificate, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Exit("Could not load key/certificate pair from files:", err)
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		log.Exit("Could not parse x509 certificate from tls certificate:", err)
	}
	caFile, err := ioutil.ReadFile(*ca)
	if err != nil {
		log.Exitf("could not read CA certificate: %s", err)
	}
	block, _ := pem.Decode(caFile)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Exit("Error parsing CA certificate", err)
	}
	return &certificate, caCert
}

// generateFromCA generates a client certificate from the provided CA.
func generateFromCA() (*tls.Certificate, *x509.Certificate) {
	GetCAEntity()
	clientEnt, err := entity.CreateSigned(targetName, nil, caEnt)
	if err != nil {
		log.Exitf("Failed to create a signed entity: %v", err)
	}
	return clientEnt.Certificate, caEnt.Certificate.Leaf
}

// ParseCertificates gets certificates from files or generates them from the CA.
func ParseCertificates() (*tls.Certificate, *x509.Certificate) {
	if *ca != "" {
		if *cert != "" && *key != "" {
			read_pin_data()
			return loadFromFile()
		}
		if *caKey != "" {
			return generateFromCA()
		}
	}
	return nil, nil
}

// LoadCertificates loads certificates from files and exits if there's an error.
func LoadCertificates() ([]tls.Certificate, *x509.CertPool) {
	certPool := x509.NewCertPool()
	certs, caBundle := ParseCertificates()
	if certs == nil || caBundle == nil {
		log.Exit("Please provide -ca & -key or -ca, -cert & -ca_key")
	}
	certPool.AddCert(caBundle)
	return []tls.Certificate{*certs}, certPool
}

// SetTargetName sets the targetName variable.
func SetTargetName(name string) {
	targetName = name
}

// ClientCredentials generates gRPC DialOptions for existing credentials.
func ClientCredentials() []grpc.DialOption {
	if *TargetName == "" {
		log.Exit("Please provide a -target_name")
	}
	opts := []grpc.DialOption{}

	if *notls {
		opts = append(opts, grpc.WithInsecure())
	} else {
		tlsConfig := &tls.Config{}
		if *insecure {
			tlsConfig.InsecureSkipVerify = true
		} else {
			certificates, certPool := LoadCertificates()
			tlsConfig.ServerName = *TargetName
			tlsConfig.Certificates = certificates
			tlsConfig.RootCAs = certPool
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	if authorizedUser.username != "" {
		return append(opts, grpc.WithPerRPCCredentials(&authorizedUser))
	}
	return opts
}

// AttachToContext attaches credentials to a context.
// If there are existing credentials, it overrides their values.
func AttachToContext(ctx context.Context) context.Context {
	if authorizedUser.username == "" {
		return ctx
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}
	md.Set(usernameKey, authorizedUser.username)
	md.Set(passwordKey, authorizedUser.password)

	return metadata.NewOutgoingContext(ctx, md)
}

// GetCAEntity gets a CA entity from a CA file and private key.
func GetCAEntity() *entity.Entity {
	if caEnt != nil {
		return caEnt
	}
	if *caKey == "" {
		log.Exit("-ca_key must be set with file locations")
	}
	var err error
	if caEnt, err = entity.FromFile(*ca, *caKey); err != nil {
		log.Exitf("Failed to load certificate and key from file: %v", err)
	}
	return caEnt
}

// ServerCredentials generates gRPC ServerOptions for existing credentials.
func ServerCredentials() []grpc.ServerOption {
	if *notls {
		return []grpc.ServerOption{}
	}

	certificates, certPool := LoadCertificates()

	if *insecure {
		return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{
			ClientAuth:   tls.VerifyClientCertIfGiven,
			Certificates: certificates,
			ClientCAs:    certPool,
		}))}
	}

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{
		VerifyPeerCertificate: CheckCertSANData,
		ClientAuth:            tls.RequireAnyClientCert,
		Certificates:          certificates,
		ClientCAs:             certPool,
	}))}
}

// AuthorizeUser checks for valid credentials in the context Metadata.
func AuthorizeUser(ctx context.Context) (string, bool) {
	authorize := false
	if authorizedUser.username == "" {
		authorize = true
	}
	headers, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "no Metadata found", authorize
	}
	user, ok := headers[usernameKey]
	if !ok || len(user) == 0 {
		return "no username in Metadata", authorize
	}
	pass, ok := headers[passwordKey]
	if !ok || len(pass) == 0 {
		return fmt.Sprintf("found username \"%s\" but no password in Metadata", user[0]), authorize
	}
	if authorize || pass[0] == authorizedUser.password && user[0] == authorizedUser.username {
		return fmt.Sprintf("authorized with \"%s:%s\"", user[0], pass[0]), true
	}
	return fmt.Sprintf("not authorized with \"%s:%s\"", user[0], pass[0]), false
}
