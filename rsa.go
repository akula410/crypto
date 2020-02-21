package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

type RSA struct {
	PrivateKey []byte
	PublicKey []byte
	Private *rsa.PrivateKey
	Public *rsa.PublicKey
}

var DefByte = 2048

func (r *RSA)Init(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	if r.Private == nil && len(r.PrivateKey) > 0 {
		r.initPrivateKey()
	}

	if r.Public == nil && len(r.PublicKey) > 0 {
		r.initPublicKey()
	}

	if r.Private == nil || r.Public == nil {
		var PrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			panic(err)
		}

		r.Private = PrivateKey
		r.Public = &PrivateKey.PublicKey
		r.PrivateKey = r.getPrivateKey()
		r.PublicKey = r.getPublicKey()
	}



	return r.Private, r.Public
}



func (r *RSA) EncryptOAEP(message []byte)[]byte{
	r.Init(DefByte)
	var label = []byte("")
	var hash = sha256.New()

	var result, err = rsa.EncryptOAEP(hash, rand.Reader, r.Public, message, label)

	if err != nil {
		panic(err)
	}
	return result
}

func (r *RSA) DecryptOAEP(message []byte)[]byte{
	r.Init(DefByte)
	var label = []byte("")
	var hash = sha256.New()

	var result, err = rsa.DecryptOAEP(hash, rand.Reader, r.Private, message, label)

	if err != nil {
		panic(err)
	}

	return result
}



func (r *RSA) EncryptPKCS(message []byte)[]byte {
	var result, err = rsa.EncryptPKCS1v15(rand.Reader, r.Public, message)

	if err != nil {
		panic(err)
	}
	return result
}

func (r *RSA) DecryptPKCS(message []byte) []byte {
	var result, err = rsa.DecryptPKCS1v15(rand.Reader, r.Private, message)

	if err != nil {
		panic(err)
	}
	return result
}

func (r *RSA) getPublicKey()[]byte{
	r.Init(DefByte)
	PublicASN1, err := x509.MarshalPKIXPublicKey(r.Public)
	if err != nil {
		panic(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: PublicASN1,
	})

	return pubBytes
}

func (r *RSA) getPrivateKey()[]byte{
	r.Init(DefByte)
	PrivateBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(r.Private),
		},
	)

	return PrivateBytes
}

func (r *RSA) initPrivateKey(){
	block, _ := pem.Decode(r.PrivateKey)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			panic(err)
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		panic(err)
	}
	r.Private = key
}

func (r *RSA) initPublicKey(){
	block, _ := pem.Decode(r.PublicKey)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			panic(err)
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		panic(err)
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		panic(err)
	}
	r.Public = key
}