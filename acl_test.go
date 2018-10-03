// TODO: test acl with glob
package gold

import (
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	aclDir = "/" + testFolderPath + "/acldir/"
)

func TestACLInit(t *testing.T) {
	testServer := getFreshServer()
	u1Path, u1Client, u1Graph, err := GetClient(TestUser1, testServer.URL+"/"+testFolderPath, false)
	assert.NoError(t, err)
	u2Path, u2Client, u2Graph, err := GetClient(TestUser2, testServer.URL+"/"+testFolderPath, true)
	assert.NoError(t, err)

	t.Run("user1 PUT to create resource", func(t *testing.T) {
		user1n3, err := u1Graph.Serialize("text/turtle")
		assert.NoError(t, err)
		req, err := http.NewRequest("PUT", u1Path, strings.NewReader(user1n3))
		assert.NoError(t, err)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, 201, resp.StatusCode)
	})

	t.Run("user2 PUT to create resource", func(t *testing.T) {
		user2n3, err := u2Graph.Serialize("text/turtle")
		assert.NoError(t, err)
		req, err := http.NewRequest("PUT", u2Path, strings.NewReader(user2n3))
		assert.NoError(t, err)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, 201, resp.StatusCode)
	})

	t.Run("user1 GET her resource", func(t *testing.T) {
		req, err := http.NewRequest("GET", u1Path, nil)
		assert.NoError(t, err)
		resp, err := u1Client.Do(req)
		assert.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, u1Path, resp.Header.Get("User"))
	})

	t.Run("user2 GET her resource", func(t *testing.T) {
		req, err := http.NewRequest("GET", u2Path, nil)
		assert.NoError(t, err)
		resp, err := u2Client.Do(req)
		assert.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, u2Path, resp.Header.Get("User"))
	})
}

func TestNoACLFile(t *testing.T) {
	testServer := getFreshServer()
	collectionLink := ""
	fileLink := ""

	t.Run("anyone can create a collection", func(t *testing.T) {
		request, err := http.NewRequest("MKCOL", testServer.URL+aclDir, nil)
		assert.NoError(t, err)

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 201, response.StatusCode)

		collectionLink = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
		assert.NotNil(t, collectionLink)
	})

	t.Run("anyone can update the collection", func(t *testing.T) {
		request, err := http.NewRequest("PUT", collectionLink, strings.NewReader(""))
		assert.NoError(t, err)
		request.Header.Add("Content-Type", "text/turtle")

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 201, response.StatusCode)
	})

	t.Run("anyone can create a resource in the collection", func(t *testing.T) {
		request, err := http.NewRequest("PUT", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
		assert.NoError(t, err)
		request.Header.Add("Content-Type", "text/turtle")

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 201, response.StatusCode)

		fileLink = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
		assert.NotNil(t, fileLink)
	})

	t.Run("anyone can update the resource in the collection", func(t *testing.T) {
		request, err := http.NewRequest("PUT", fileLink, strings.NewReader(""))
		assert.NoError(t, err)
		request.Header.Add("Content-Type", "text/turtle")

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 201, response.StatusCode)
	})

	t.Run("anyone can get info about the resource in the collection", func(t *testing.T) {
		request, err := http.NewRequest("HEAD", fileLink, nil)
		assert.NoError(t, err)

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestResourceKey(t *testing.T) {
	testServer := getFreshServer()
	user1, u1Client, _, err := GetClient(TestUser1, testServer.URL+"/"+testFolderPath, false)
	assert.NoError(t, err)
	_, u2Client, _, err := GetClient(TestUser2, testServer.URL+"/"+testFolderPath, true)
	assert.NoError(t, err)

	key := "aaabbbccc"
	acl := ""

	collectionLink := ""

	t.Run("anyone can create a collection", func(t *testing.T) {
		request, err := http.NewRequest("MKCOL", testServer.URL+aclDir, nil)
		assert.NoError(t, err)

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 201, response.StatusCode)

		collectionLink = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
		assert.NotNil(t, collectionLink)
	})

	t.Run("anyone can update the collection", func(t *testing.T) {
		request, err := http.NewRequest("PUT", collectionLink, strings.NewReader(""))
		assert.NoError(t, err)
		request.Header.Add("Content-Type", "text/turtle")

		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 201, response.StatusCode)
	})

	t.Run("user1 lists the ACL dir", func(t *testing.T) {
		request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
		assert.NoError(t, err)
		response, err := u1Client.Do(request)
		assert.NoError(t, err)
		log.Println(response.Body)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)

		acl = ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	})

	t.Run("user1 adds a public key to the ACL resource", func(t *testing.T) {
		body := "<#Owner>" +
			"	a <http://www.w3.org/ns/auth/acl#Authorization> ;" +
			"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">, <" + collectionLink + ">;" +
			"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
			"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
			"<#PublicWithKey>" +
			"	a <http://www.w3.org/ns/auth/acl#Authorization> ;" +
			"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">;" +
			"	<http://www.w3.org/ns/auth/acl#resourceKey> \"" + key + "\";" +
			"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."

		request, err := http.NewRequest("PUT", collectionLink, strings.NewReader(body))
		assert.NoError(t, err)
		request.Header.Add("Content-Type", "text/turtle")

		response, err := u1Client.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)
	})

	//t.Run("anyone can create a resource in the collection", func(t *testing.T) {
	//	request, err := http.NewRequest("PUT", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
	//	assert.NoError(t, err)
	//	request.Header.Add("Content-Type", "text/turtle")
	//
	//	response, err := u1Client.Do(request)
	//	assert.NoError(t, err)
	//	response.Body.Close()
	//	assert.Equal(t, 201, response.StatusCode)
	//
	//	fileLink := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	//	assert.NotNil(t, fileLink)
	//})

	t.Run("user1 is able to list the resource in the dir", func(t *testing.T) {
		request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
		assert.NoError(t, err)
		response, err := u1Client.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)
	})

	t.Run("user1 is able to list the resource in the dir using thw link provided", func(t *testing.T) {
		request, err := http.NewRequest("HEAD", collectionLink, nil)
		assert.NoError(t, err)
		response, err := u1Client.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)
	})

	t.Run("user2 can list the resource using the key", func(t *testing.T) {
		request, err := http.NewRequest("HEAD", testServer.URL+aclDir+"?key="+key, nil)
		assert.NoError(t, err)
		response, err := u2Client.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)
	})

	t.Run("anyone can list the resource using the key", func(t *testing.T) {
		request, err := http.NewRequest("HEAD", testServer.URL+aclDir+"?key="+key, nil)
		assert.NoError(t, err)
		response, err := httpClient.Do(request)
		assert.NoError(t, err)
		response.Body.Close()
		assert.Equal(t, 200, response.StatusCode)
	})
}

func TestACLOrigin(t *testing.T) {
	testServer := getFreshServer()
	user1, u1Client, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	origin1 := "http://example.org/"
	origin2 := "http://example.com/"

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err := u1Client.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#origin> <" + origin1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#Public>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>;" +
		"	<http://www.w3.org/ns/auth/acl#origin> <" + origin1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = u1Client.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = u1Client.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", origin1)
	response, err = u1Client.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", origin2)
	response, err = u1Client.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	// agent
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", origin1)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	request.Header.Add("Origin", origin2)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)
}

func TestACLOwnerOnly(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#owner> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+"/_test/acldir", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	// agent
	request, err = http.NewRequest("PUT", acl, strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)
}

func TestACLReadOnly(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	a <http://www.w3.org/ns/auth/acl#Authorization> ;" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#Public>" +
		"	a <http://www.w3.org/ns/auth/acl#Authorization> ;" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	// agent
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", acl, strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)
}

func TestACLGlob(t *testing.T) {
	testServer := getFreshServer()
	_, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("GET", testServer.URL+aclDir+"*", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err := user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	g := NewGraph(testServer.URL + aclDir)
	g.Parse(response.Body, "text/turtle")
	authz := g.One(nil, nil, ns.acl.Get("Authorization"))
	assert.Nil(t, authz)

	request, err = http.NewRequest("GET", testServer.URL+aclDir+"*", nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
	g = NewGraph(testServer.URL + aclDir)
	g.Parse(response.Body, "text/turtle")
	authz = g.One(nil, nil, ns.acl.Get("Authorization"))
	assert.Nil(t, authz)

	request, err = http.NewRequest("DELETE", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLAppendOnly(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + "abc>, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#AppendOnly>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + testServer.URL + aclDir + "abc>;" +
		"	<http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Append> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// agent
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<g> <h> <i> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLRestricted(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	user2, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abc>, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#Restricted>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abc>;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user2 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// agent
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)

	request, err = http.NewRequest("DELETE", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLPathWithSpaces(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
	request.Header.Add("Slug", "one two")
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")
	spacesDir := response.Header.Get("Location")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + spacesDir + ">, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", spacesDir, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", spacesDir, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	// cleanup
	request, err = http.NewRequest("DELETE", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", spacesDir, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLGroup(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	user2, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	groupTriples := "<#> a <http://xmlns.com/foaf/0.1/Group>;" +
		"	<http://xmlns.com/foaf/0.1/member> <a>, <b>, <" + user2 + ">."

	request, err = http.NewRequest("PUT", testServer.URL+aclDir+"group", strings.NewReader(groupTriples))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abc>, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#defaultForNew> <" + aclDir + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#Group>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abc>;" +
		"	<http://www.w3.org/ns/auth/acl#agentClass> <" + testServer.URL + aclDir + "group#>;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	request.Header.Add("Accept", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+aclDir+"abc", strings.NewReader("<a> <b> <c> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	response, err = user2h.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	// agent
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abc", strings.NewReader("<d> <e> <f> ."))
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	response.Body.Close()
	assert.NoError(t, err)
	assert.Equal(t, 401, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir+"group", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLDefaultForNew(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	request, err := http.NewRequest("HEAD", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + ">, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#defaultForNew> <" + aclDir + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ." +
		"<#Default>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + ">;" +
		"	<http://www.w3.org/ns/auth/acl#defaultForNew> <" + aclDir + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	// user1
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("PUT", testServer.URL+aclDir+"abcd", strings.NewReader("<a> <b> <c> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abcd", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	// user2
	request, err = http.NewRequest("HEAD", acl, nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abcd", nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abcd", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	// agent
	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abcd", nil)
	assert.NoError(t, err)
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abcd", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = httpClient.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)
}

func TestACLWebIDDelegation(t *testing.T) {
	testServer := getFreshServer()
	user1, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)
	user2, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	assert.NoError(t, err)

	// add delegation
	sparqlData := `INSERT DATA { <` + user1 + `> <http://www.w3.org/ns/auth/acl#delegates> <` + user2 + `> . }`
	request, err := http.NewRequest("PATCH", user1, strings.NewReader(sparqlData))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "application/sparql-update")
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("HEAD", testServer.URL+aclDir+"abcd", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	acl := ParseLinkHeader(response.Header.Get("Link")).MatchRel("acl")

	body := "<#Owner>" +
		"	<http://www.w3.org/ns/auth/acl#accessTo> <" + aclDir + "abcd>, <" + acl + ">;" +
		"	<http://www.w3.org/ns/auth/acl#agent> <" + user1 + ">;" +
		"	<http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> ."
	request, err = http.NewRequest("PUT", acl, strings.NewReader(body))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 201, response.StatusCode)

	request, err = http.NewRequest("GET", testServer.URL+aclDir+"abcd", nil)
	assert.NoError(t, err)
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)

	request, err = http.NewRequest("POST", testServer.URL+aclDir+"abcd", strings.NewReader("<d> <e> <f> ."))
	assert.NoError(t, err)
	request.Header.Add("Content-Type", "text/turtle")
	request.Header.Add("On-Behalf-Of", "<"+user1+">")
	response, err = user2h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLCleanUp(t *testing.T) {
	testServer := getFreshServer()
	_, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	assert.NoError(t, err)

	request, err := http.NewRequest("DELETE", testServer.URL+aclDir+"abcd", nil)
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir+"abc", nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)

	request, err = http.NewRequest("DELETE", testServer.URL+aclDir, nil)
	assert.NoError(t, err)
	response, err = user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}

func TestACLwalkPath(t *testing.T) {
	_, config := getFreshServerWithConfig()
	//_, user1h, _, err := GetClient(TestUser1, testServer.URL+"/_test", false)
	//assert.NoError(t, err)
	//_, user2h, _, err := GetClient(TestUser2, testServer.URL+"/_test", true)
	//assert.NoError(t, err)
	config.Debug = false
	s := NewServer(config)
	req := &httpRequest{nil, s, "", "", "", false}

	path := "http://example.org/foo/bar/baz"
	p, _ := req.pathInfo(path)

	depth := strings.Split(p.Path, "/")
	var results []string

	for i := len(depth); i > 0; i-- {
		depth = depth[:len(depth)-1]
		path = walkPath(p.Base, depth)
		results = append(results, path)
	}
	assert.Equal(t, "http://example.org/foo/bar/", results[0])
	assert.Equal(t, "http://example.org/foo/", results[1])
	assert.Equal(t, "http://example.org/", results[2])
}
