package site

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/rasoat/rasoat/internal/roots"
)

const (
	maxBody = 3_000_000
	timeout = 8 * time.Second
	maxHops = 5
)

// Resp is one page or script as read.
type Resp struct {
	URL           string
	Status        int
	Headers       map[string]string // lower-case names
	Body          string
	TLSUnverified bool
}

// Get fetches one URL, following redirects under the caller's policy.
type Get func(string) (*Resp, error)

// NewGet returns a Get. public: only public addresses may be read, on every hop and at every connection, so an agent
// cannot be steered at the user's machine or network even by a DNS answer that changes between the check and the connect.
func NewGet(userAgent string, public bool) Get {
	roots.Ensure()
	dialer := &net.Dialer{Timeout: timeout}
	proxy := http.ProxyFromEnvironment
	if public {
		proxy = nil
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return &Refused{"invalid"}
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !IsPublicAddress(ip) {
				return &Refused{"private"}
			}
			return nil
		}
	}
	client := func(insecure bool) *http.Client {
		return &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy: proxy, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, TLSHandshakeTimeout: timeout,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		}
	}
	strict, lax := client(false), client(true)
	return func(input string) (*Resp, error) {
		href := input
		for hop := 0; ; hop++ {
			if hop > maxHops {
				return nil, errors.New("too many redirects")
			}
			u, err := url.Parse(href)
			if err != nil {
				return nil, err
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return nil, errors.New("not http(s)")
			}
			if public {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				err := AssertPublic(ctx, u)
				cancel()
				if err != nil {
					return nil, err
				}
			}
			resp, unverified, err := fetch(strict, lax, u, userAgent)
			if err != nil {
				return nil, err
			}
			location := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
				resp.Body.Close()
				next, err := u.Parse(location)
				if err != nil {
					return nil, err
				}
				href = next.String()
				continue
			}
			// Past the cap we keep what we have: a version string sits early in a chunk more often than not.
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			resp.Body.Close()
			headers := map[string]string{}
			for k, v := range resp.Header {
				headers[strings.ToLower(k)] = strings.Join(v, ", ")
			}
			return &Resp{URL: u.String(), Status: resp.StatusCode, Headers: headers, Body: string(body), TLSUnverified: unverified}, nil
		}
	}
}

// A server that omits its intermediate certificate loads in browsers (they fetch it) but fails here. We only read public
// files, so read once more without chain verification, and say so.
func fetch(strict, lax *http.Client, u *url.URL, userAgent string) (*http.Response, bool, error) {
	do := func(c *http.Client) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "text/html,*/*")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		resp, err := c.Do(req.WithContext(ctx))
		if err != nil {
			cancel()
			return nil, err
		}
		resp.Body = &cancelOnClose{resp.Body, cancel}
		return resp, nil
	}
	resp, err := do(strict)
	var authority x509.UnknownAuthorityError
	if err != nil && errors.As(err, &authority) {
		resp, err = do(lax)
		return resp, true, err
	}
	return resp, false, err
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}
