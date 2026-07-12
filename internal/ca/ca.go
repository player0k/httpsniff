// Package ca реализует корневой удостоверяющий центр (CA), которым перехватчик
// подписывает «на лету» листовые сертификаты для каждого MITM-домена.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// Authority — корневой CA и кеш выпущенных листовых сертификатов.
type Authority struct {
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	leafKey *rsa.PrivateKey // единый ключ для всех листовых сертификатов (быстрее)

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate загружает CA из указанных PEM-файлов. Если их нет — генерирует
// новый CA и сохраняет на диск, чтобы пользователь мог установить его в доверенные.
// Второе значение — true, если CA был сгенерирован в этом вызове.
// Поддерживается и подкладка своих сертификатов по этим путям.
func LoadOrCreate(certPath, keyPath string) (*Authority, bool, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		a, err := load(certPath, keyPath)
		return a, false, err
	}

	a, err := Generate()
	if err != nil {
		return nil, false, err
	}
	if err := a.Save(certPath, keyPath); err != nil {
		return nil, false, err
	}
	return a, true, nil
}

func load(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("чтение сертификата CA %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("чтение ключа CA %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM сертификата CA: %s", certPath)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("разбор сертификата CA %s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM ключа CA: %s", keyPath)
	}
	caKey, err := parseRSAKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("разбор ключа CA %s: %w", keyPath, err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("генерация листового ключа: %w", err)
	}

	return &Authority{
		caCert:  caCert,
		caKey:   caKey,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func parseRSAKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ключ CA не является RSA-ключом")
	}
	return rk, nil
}

// Generate создаёт новый самоподписанный корневой CA в памяти (без записи на диск).
func Generate() (*Authority, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("генерация ключа CA: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("серийный номер CA: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "httpsniff Root CA",
			Organization: []string{"httpsniff"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("создание сертификата CA: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("разбор сертификата CA: %w", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("генерация листового ключа: %w", err)
	}

	return &Authority{
		caCert:  caCert,
		caKey:   caKey,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// Save записывает сертификат и ключ CA в PEM-файлы.
func (a *Authority) Save(certPath, keyPath string) error {
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.caCert.Raw})
	if err := os.WriteFile(certPath, certOut, 0644); err != nil {
		return fmt.Errorf("запись сертификата CA %s: %w", certPath, err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(a.caKey),
	})
	if err := os.WriteFile(keyPath, keyOut, 0600); err != nil {
		return fmt.Errorf("запись ключа CA %s: %w", keyPath, err)
	}
	return nil
}

// GetCertificate — callback для tls.Config: выдаёт (и кеширует) листовой
// сертификат для запрошенного через SNI имени, подписанный нашим CA.
func (a *Authority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "localhost"
	}
	return a.certFor(host)
}

func (a *Authority) certFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if c, ok := a.cache[host]; ok {
		return c, nil
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("серийный номер листа: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &a.leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("создание листового сертификата для %s: %w", host, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, a.caCert.Raw},
		PrivateKey:  a.leafKey,
	}
	a.cache[host] = tlsCert
	return tlsCert, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
