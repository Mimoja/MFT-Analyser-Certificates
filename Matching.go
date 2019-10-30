package main

import (
	"github.com/Mimoja/MFT-Common"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"github.com/hillu/go-yara"
	zcrypto "github.com/zmap/zcrypto/x509"
	"io/ioutil"
	"os"
)

var yaraRules *yara.Rules

func setupYara() {
	c, err := yara.NewCompiler()
	if err != nil {
		Bundle.Log.Fatal("Could not create yara compiler")
	}

	file, err := os.Open("rules.yara")
	if err != nil {
		Bundle.Log.Fatalf("Could not load rules: %v", err)
	}

	c.AddFile(file, "test")

	r, err := c.GetRules()
	if err != nil {
		Bundle.Log.Fatalf("Failed to compile rules: %s", err)
	}
	yaraRules = r
}

func analyse(entry MFTCommon.FlashImage) error {
	Bundle.Log.Infof("Searching for Magic Bytes:  %s", entry.ID.GetID())

	reader, err := Bundle.Storage.GetFile(entry.ID.GetID())
	if err != nil {
		Bundle.Log.Errorf("could not fetch file: %s : %v", entry.ID.GetID(), err)
		return err
	}
	defer reader.Close()

	bts, err := ioutil.ReadAll(reader)
	if err != nil {
		Bundle.Log.Errorf("could not read file: %s : %v", entry.ID.GetID(), err)
		return err
	}

	entry.Certificates = make([]string, 0)

	matches, err := yaraRules.ScanMem(bts, 0, 0)
	if err != nil {
		Bundle.Log.Errorf("could not scan with yara %v", err)
		return err
	}

	if len(matches) == 0 {
		Bundle.Log.Info("Could not find any matches!")
		return nil
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	for _, match := range matches {
		for _, str := range match.Strings {
			reader := bytes.NewReader(bts)
			reader.Seek(int64(str.Offset), 0)

			switch match.Rule {
			case "DER":
				size := uint16(str.Data[2])<<8 | uint16(str.Data[3])

				if str.Offset+uint64(size)+4 > uint64(len(bts)) {
					Bundle.Log.Errorf("Could not read DER: Out of bounds")
					continue
				}
				derBytes := bts[str.Offset : str.Offset+uint64(size)+4]

				switch str.Name {
				case "$CERT":
					certs, err := zcrypto.ParseCertificates(derBytes)

					if err != nil {
						Bundle.Log.Errorf("Could not parse DER: %v, %s", err, entry.ID.GetID())
						continue
					}

					//	enc.Encode(certs)
					for _, cert := range certs {
						id := MFTCommon.GenerateID(cert.Raw)
						idString := id.GetID()
						Bundle.Log.Infof("Found Certificate %s", idString)

						b, err := cert.MarshalJSON()

						if err != nil {
							Bundle.Log.Errorf("Could not marchal cert to json: %v", err)
							continue
						}
						out := map[string]interface{}{}
						json.Unmarshal(b, &out)

						out["ID"] = id
						typeString := "certificate"
						Bundle.DB.StoreElement("certificates", &typeString, out, &idString)

						entry.Certificates = appendIfMissing(entry.Certificates, idString)
					}

				case "$KEY_RSA_PUB":
					pubkey, err := x509.ParsePKCS1PublicKey(derBytes)
					if err != nil {
						Bundle.Log.WithField("entry", entry).Infof("Could not parse PKCS1 trying PKIX: %v\n", err)
						_, err2 := x509.ParsePKIXPublicKey(derBytes)
						if err2 != nil {
							Bundle.Log.WithField("entry", entry).Errorf("Could not parse public key\nPKIX: %v\nPKCS1: %v", err, err2)
							break
						}
						Bundle.Log.WithField("entry", entry).Infof("Found Public Key at 0x%08X", str.Offset)
						//enc.Encode(pub2)
						break
					}
					Bundle.Log.WithField("entry", entry).WithField("RSAPubKey", pubkey).Infof("Found RSA Public Key at 0x%08X", str.Offset)
					//enc.Encode(pub)
					break
				case "$KEY_PUB":
					_, err := x509.ParsePKIXPublicKey(derBytes)
					if err != nil {
						Bundle.Log.WithField("entry", entry).Infof("Could not parse PKIX trying PKCS1: %v\n", err)
						pubkey, err2 := x509.ParsePKCS1PublicKey(derBytes)
						if err2 != nil {
							Bundle.Log.WithField("entry", entry).Errorf("Could not parse public key\nPKIX: %v\nPKCS1: %v", err, err2)
							break
						}
						Bundle.Log.WithField("entry", entry).WithField("RSAPubKey", pubkey).Infof("Found RSA Public Key at 0x%08X", str.Offset)
						//enc.Encode(pub2)
						break
					}
					Bundle.Log.WithField("entry", entry).Infof("Found Public Key at 0x%08X", str.Offset)
					//enc.Encode(pub)
					break
				default:
					Bundle.Log.Errorf("Unhandled rule string: " + str.Name)
				}
			default:
				//panic("Unhandled ruleset "+match.Rule+" string: " + str.Name)
				Bundle.Log.Errorf("Unhandled ruleset "+match.Rule+" string: "+str.Name+" at 0x%08X data: 0x%08X", str.Offset, str.Data)

			}

			//enc.Encode(match)

		}
	}
	Bundle.Log.Infof("Appending to elastic")
	_, err = Bundle.DB.ES.Update().
		Index("flashimages").
		Type("flashimage").
		Id(entry.ID.GetID()).
		Doc(map[string]interface{}{"Certificates": entry.Certificates}).
		Do(context.Background())

	if err != nil {
		Bundle.Log.WithField("entry", entry).
			WithError(err).
			Errorf("Cannot update Certificates: %v", err)
		return err
	}
	return nil
}

func containsCert(slice []string, i string) bool {
	for _, ele := range slice {
		if ele == i {
			return true
		}
	}
	return false
}

func appendIfMissing(slice []string, i string) []string {
	if !containsCert(slice, i) {
		return append(slice, i)
	}
	return slice
}
