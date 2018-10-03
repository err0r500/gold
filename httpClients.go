// +build !test

package gold

// this file won't be included in builds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"net/http"
	"strconv"
)

type TestUser int

const (
	TestUser1 TestUser = iota
	TestUser2
)

func (u TestUser) shortName() string {
	name := []string{"user1", "user2"}
	switch {
	case u <= TestUser2:
		return name[u]
	default:
		return strconv.Itoa(int(u))
	}
}

func (u TestUser) longName() string {
	name := []string{"User 1", "User 2"}
	switch {
	case u <= TestUser2:
		return name[u]
	default:
		return strconv.Itoa(int(u))
	}
}

func GetKeys(user TestUser, folderPath string) (string, *Graph, *rsa.PrivateKey, *rsa.PublicKey, error) {
	idPath := folderPath + "/" + user.shortName() + "#id"
	userAccount := webidAccount{
		WebID:         idPath,
		BaseURI:       folderPath + "/",
		PrefURI:       folderPath + "/Preferences/prefs.ttl",
		PubTypeIndex:  folderPath + "/Preferences/pubTypeIndex.ttl",
		PrivTypeIndex: folderPath + "/Preferences/privTypeIndex.ttl",
	}

	graph, privateKey, publicKey, err := AddProfileKeys(idPath, NewWebIDProfile(userAccount))
	if err != nil {
		return "", nil, nil, nil, err
	}

	return idPath, graph, privateKey, publicKey, nil
}

func GetClient(user TestUser, folderPath string, withRand bool) (string, *http.Client, *Graph, error) {
	idPath, graph, privateKey, _, err := GetKeys(user, folderPath)
	if err != nil {
		return "", nil, nil, err
	}

	tlsCertificate, err := NewRSAcert(idPath, user.longName(), privateKey)
	if err != nil {
		return "", nil, nil, err
	}

	config := tls.Config{
		Certificates:       []tls.Certificate{*tlsCertificate},
		InsecureSkipVerify: true,
	}
	if withRand {
		config.Rand = rand.Reader
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &config,
		},
	}

	return idPath, &client, graph, nil
}
