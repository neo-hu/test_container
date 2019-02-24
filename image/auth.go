package image

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultRegistryVersionHeader = "Docker-Distribution-Api-Version"
	minimumTokenLifetimeSeconds  = 60
)

var (
	v2, _ = url.Parse("/v2/")
)

type tokenHandler struct {
	tokenLock        sync.Mutex
	tokenExpiration  time.Time
	domain           *url.URL
	tokenCache, path string
}

type getTokenResponse struct {
	Token        string    `json:"token"`
	AccessToken  string    `json:"access_token"`
	ExpiresIn    int       `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshToken string    `json:"refresh_token"`
}

func (th *tokenHandler) getToken() (string, error) {
	th.tokenLock.Lock()
	defer th.tokenLock.Unlock()
	now := time.Now()
	// todo 判断token是否过期
	if now.After(th.tokenExpiration) {
		token, expiration, err := th.fetchToken()
		if err != nil {
			return "", err
		}
		th.tokenCache = token
		th.tokenExpiration = expiration
	}
	return th.tokenCache, nil
}

func (th *tokenHandler) fetchToken() (string, time.Time, error) {
	// todo step 1 获取认证url
	uri := th.domain.ResolveReference(v2).String()
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	foundV2 := false
	for _, supportedVersions := range resp.Header[http.CanonicalHeaderKey(DefaultRegistryVersionHeader)] {
		for _, version := range strings.Fields(supportedVersions) {
			if version == "registry/2.0" {
				foundV2 = true
			}
		}
	}
	if !foundV2 {
		return "", time.Time{}, errors.New("registry version not support 2.0")
	}
	var params map[string]string
	for _, h := range resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
		k, v := parseValueAndParams(h)
		if k == "bearer" {
			params = v
			break
		}
	}
	if params == nil {
		return "", time.Time{}, fmt.Errorf("get %s no params token auth", uri)
	}
	logrus.Debugf("get %s, params:%v", uri, params)

	// todo step 2 根据认证的url获取token
	realm, ok := params["realm"]
	if !ok {
		return "", time.Time{}, errors.New("no realm specified for token auth")
	}
	realmURL, err := url.Parse(realm)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid token auth realm: %s", err)
	}

	req, err = http.NewRequest("GET", realmURL.String(), nil)
	if err != nil {
		return "", time.Time{}, err
	}
	reqParams := req.URL.Query()
	service := params["service"]
	if service != "" {
		reqParams.Add("service", service)
	}
	reqParams.Add("scope", fmt.Sprintf("repository:%s:pull", th.path))
	req.URL.RawQuery = reqParams.Encode()
	realmResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer realmResp.Body.Close()

	if !SuccessStatus(realmResp.StatusCode) {
		return "", time.Time{}, HandleErrorResponse(realmResp)
	}

	decoder := json.NewDecoder(realmResp.Body)
	var tr getTokenResponse
	if err = decoder.Decode(&tr); err != nil {
		return "", time.Time{}, fmt.Errorf("unable to decode token response: %s", err)
	}

	if tr.AccessToken != "" {
		tr.Token = tr.AccessToken
	}
	if tr.Token == "" {
		return "", time.Time{}, errors.New("authorization server did not include a token in the response")
	}

	if tr.ExpiresIn < minimumTokenLifetimeSeconds {
		// The default/minimum lifetime.
		tr.ExpiresIn = minimumTokenLifetimeSeconds
		logrus.Infof("Increasing token expiration to: %d seconds", tr.ExpiresIn)
	}
	if tr.IssuedAt.IsZero() {
		tr.IssuedAt = time.Now()
	}
	logrus.Debugf("fetchToken %s, ExpiresIn:%v", tr.Token, tr.ExpiresIn)
	return tr.Token, tr.IssuedAt.Add(time.Duration(tr.ExpiresIn) * time.Second), nil

}

// 设置Authorization Header
func (th *tokenHandler) ModifyRequest(req *http.Request) error {
	token, err := th.getToken()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	return nil
}

func NewTokenHandlerWithOptions(domain *url.URL, path string) RequestModifier {
	return &tokenHandler{
		domain: domain,
		path:   path,
	}
}
