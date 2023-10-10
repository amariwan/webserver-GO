package webserver

/* read this first
https://benhoyt.com/writings/go-routing/
https://blog.merovius.de/2017/06/18/how-not-to-use-an-http-router.html
*/

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/go-http-utils/cors"
	"github.com/pkg/profile"
	"gitmaster.hq.aland-mariwan.de/go/sessionstore.git"
	"gitmaster.hq.aland-mariwan.de/go/userdb.git"
	"go.uber.org/goleak"
)

type myWebSrvCtx struct {
	userdb *userdb.UserDbBolt
	ws     *WebServer
}

type apiHandler struct {
	myWebSrvCtx
}

func (ctx apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	r.Body.Read(buf)
	defer r.Body.Close()
	w.WriteHeader(http.StatusOK)
}

type loginHandler struct {
	myWebSrvCtx
}

type loginErrorHandler struct {
	myWebSrvCtx
}

// HttpLoginHandlerSample Login
func (ctx loginErrorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	r.Body.Read(buf)
	defer r.Body.Close()
	w.WriteHeader(http.StatusForbidden)
}

func (ctx *loginHandler) Login(cred *Credentials, token string) (sessionstore.SessionUserData, http.Handler, error) {
	var data userdb.UserEntry
	var err error
	if len(cred.ApiKey) > 0 {
		data, err = ctx.userdb.AuthKey(cred.ApiKey)
		if err != nil {
			return nil, nil, err
		}
	} else {
		data, err = ctx.userdb.Auth(cred.User, cred.Password)
		if err != nil {
			return nil, nil, err
		}
	}
	return data, &loginErrorHandler{}, nil
}

func (ctx *loginHandler) CredentialsFromBodyExtractor(body []byte) (c Credentials) {
	return Credentials{}
}

// HttpLoginHandlerSample Login
func (ctx loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	r.Body.Read(buf)
	defer r.Body.Close()
	data := GetUserDataFromRequestContext(r)
	if data != nil {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type logoutHandler struct {
	myWebSrvCtx
}

func (ctx logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var buf []byte
	r.Body.Read(buf)
	defer r.Body.Close()
	w.WriteHeader(http.StatusOK)
	sessionToken := GetSessionTokenFromRequestContext(r)
	if sessionToken != "" {
		//myCtx := ContextGetData(r.Context()).(*myWebSrvCtx)
		ctx.ws.EndSession(sessionToken)
	}

	w.WriteHeader(http.StatusOK)
}

type myUserEntry struct {
	FirstName string
	LastName  string
}

func call(method, urlstr string, header map[string][]string, cookies []*http.Cookie) (*http.Response, error) {
	client := &http.Client{
		Timeout: time.Second * 1000,
	}

	req, err := http.NewRequest(method, urlstr, nil)
	if err != nil {
		return nil, fmt.Errorf("Got error %s", err.Error())
	}
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, fmt.Errorf("Got error %s", err.Error())
	}
	if u != nil {
		pw, present := u.User.Password()
		if present {
			req.SetBasicAuth(u.User.Username(), pw)
		}
	}
	req.Header.Set("user-agent", "golang test application")
	req.Close = true
	for key, vals := range header {
		for _, val := range vals {
			req.Header.Set(key, val)
		}
	}
	if cookies != nil {
		if client.Jar == nil {
			client.Jar, err = cookiejar.New(nil)
			if err != nil {
				return nil, fmt.Errorf("Got error %s", err.Error())
			}
		}
		client.Jar.SetCookies(u, cookies)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Got error %s", err.Error())
	}
	defer response.Body.Close()
	return response, nil
}

func sessionCloser(sessionstore.SessionUserData) {

}

func startWebServer(t *testing.T) *myWebSrvCtx {
	myWsCtx := myWebSrvCtx{}
	myUsr := myUserEntry{LastName: "Rolf", FirstName: "Rolf"}
	var err error
	myWsCtx.userdb, err = userdb.New("userdb.bolt", myUsr)
	if err != nil {
		t.Errorf("could not open userdb")
		return nil
	}
	entry := userdb.UserEntry{Data: myUsr, UserID: "rolf"}
	myWsCtx.userdb.Add(entry, "geheim")

	cfg := WebServerConfig{Address: "localhost", Port: 8080, Secure: false, SslCertsPath: ""}
	myWsCtx.ws = New(cfg, myWsCtx, sessionCloser)
	if myWsCtx.ws == nil {
		t.Errorf("could not create webserver")
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/login/", myWsCtx.ws.HttpLoginChecker(loginHandler{myWsCtx}))
	mux.Handle("/logout/", myWsCtx.ws.HttpSessionChecker(logoutHandler{myWsCtx}))
	mux.Handle("/api/", myWsCtx.ws.HttpSessionChecker(apiHandler{myWsCtx}))
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		// The "/" pattern matches everything, so we need to check
		// that we're at the root here.
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, "Welcome to the home page!")
	})
	myWsCtx.ws.SetLoginChecker(&loginHandler{myWsCtx})
	//myWsCtx.ws.SetSessionChecker(sessionHandler{myWsCtx}) use default session handling

	allowedCredentials := cors.SetCredentials(true)
	allowedMethods := cors.SetMethods([]string{
		"POST",
		"GET",
		"PUT",
		"OPTIONS",
	})

	allowedOriginValidator := cors.SetAllowOrigin(true)
	allowedHeaders := cors.SetAllowHeaders([]string{
		"Accept",
		"Accept-Language",
		"Content-Language",
		"Origin",
		"Content-Type",
		"authorization",
	})

	myWsCtx.ws.Run(mux, allowedCredentials, allowedMethods, allowedHeaders, allowedOriginValidator)
	time.Sleep(time.Duration(1 * time.Second)) // wait for webserver to come up
	return &myWsCtx
}

func stopWebServer(t *testing.T, myWsCtx *myWebSrvCtx) {
	myWsCtx.ws.Close()
	myWsCtx.userdb.Close()
}

func TestWebServer(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx := startWebServer(t)
	stopWebServer(t, myWsCtx)
}
func TestAuthorizationHeader(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx := startWebServer(t)

	headers := make(map[string][]string)
	value := []string{"basic " + base64.RawStdEncoding.EncodeToString([]byte("rolf:geheim")) + "="}
	headers["Authorization"] = value
	resp, err := call(http.MethodGet, "http://localhost:8080/login", headers, nil)
	if err != nil {
		t.Errorf(err.Error())
	} else {
		if resp == nil {
			t.Errorf("response ist nil")
		} else {
			var buf []byte
			resp.Body.Read(buf)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected http status code: " + resp.Status)
			}
		}
	}
	keks, err := GetSessionToken(resp.Cookies(), &resp.Header, cookieName)
	if err != nil {
		t.Errorf("no session token found")
	} else {
		fmt.Print("test completed, session token: ", keks, "\n")
	}
	stopWebServer(t, myWsCtx)
}

func TestUserPasswordUrl(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx := startWebServer(t)

	resp, err := call(http.MethodGet, "http://rolf:geheim@localhost:8080/login", nil, nil)
	if err != nil {
		t.Errorf(err.Error())
		return
	} else {
		if resp == nil {
			t.Errorf("response ist nil")
		} else {
			var buf []byte
			resp.Body.Read(buf)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected http status code: " + resp.Status)
			}
		}
	}
	keks, err := GetSessionToken(resp.Cookies(), &resp.Header, cookieName)
	if err != nil {
		t.Errorf("no session token found")
	} else {
		fmt.Print("test completed, session token: ", keks, "\n")
	}
	stopWebServer(t, myWsCtx)
}

func login(t *testing.T) (*myWebSrvCtx, string, error) {
	myWsCtx := startWebServer(t)

	resp, err := call(http.MethodGet, "http://localhost:8080/login?user=rolf&password=geheim", nil, nil)
	if err != nil {
		t.Errorf(err.Error())
		return myWsCtx, "", err
	} else {
		if resp == nil {
			t.Errorf("response ist nil")
			return myWsCtx, "", errors.New("nil response")
		} else {
			var buf []byte
			resp.Body.Read(buf)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected http status code: " + resp.Status)
				return myWsCtx, "", errors.New("unexpected HTTP Status: " + resp.Status)
			}
		}
	}
	keks, err := GetSessionToken(resp.Cookies(), &resp.Header, cookieName)
	if err != nil {
		t.Errorf("no session token found")
	} else {
		fmt.Print("login completed, session token: ", keks, "\n")
	}
	return myWsCtx, keks, err
}

func TestUserPasswordParam(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx, keks, err := login(t)
	defer stopWebServer(t, myWsCtx)
	if err == nil {
		fmt.Print("test completed, session token: ", keks, "\n")
	}
}

func TestSessionTokenAuthHdr(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx, keks, err := login(t)
	defer stopWebServer(t, myWsCtx)
	if err == nil {
		// run request using session token
		headers := make(map[string][]string)
		value := []string{"bearer " + keks}
		headers["Authorization"] = value
		resp, err := call(http.MethodGet, "http://localhost:8080/api", headers, nil)
		if err != nil {
			t.Errorf(err.Error())
			return
		} else {
			if resp == nil {
				t.Errorf("response ist nil")
				return
			} else {
				var buf []byte
				resp.Body.Read(buf)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("unexpected http status code: " + resp.Status)
					return
				}
			}
		}
	}
}

func TestSessionTokenCookie(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx, keks, err := login(t)
	defer stopWebServer(t, myWsCtx)
	if err == nil {
		// run request using session token
		cookie := &http.Cookie{
			Name:   cookieName,
			Value:  keks,
			MaxAge: 0,
		}
		resp, err := call(http.MethodGet, "http://localhost:8080/api", nil, []*http.Cookie{cookie})
		if err != nil {
			t.Errorf(err.Error())
			return
		} else {
			if resp == nil {
				t.Errorf("response ist nil")
				return
			} else {
				var buf []byte
				resp.Body.Read(buf)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("unexpected http status code: " + resp.Status)
					return
				}
			}
		}
	}
}

func TestSessionTokenNone(t *testing.T) {
	defer goleak.VerifyNone(t)
	myWsCtx, _, err := login(t)
	defer stopWebServer(t, myWsCtx)
	if err == nil {
		resp, err := call(http.MethodGet, "http://localhost:8080/api", nil, nil)
		if err != nil {
			t.Errorf(err.Error())
			return
		} else {
			if resp == nil {
				t.Errorf("response ist nil")
				return
			} else {
				var buf []byte
				resp.Body.Read(buf)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected http status code: " + resp.Status)
					return
				}
			}
		}
	}
}

func profileThis(m *testing.M) int {
	defer profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook).Stop()
	var beforeTotal, afterTotal uint64
	before := &runtime.MemStats{}
	after := &runtime.MemStats{}
	runtime.GC()
	runtime.ReadMemStats(before)

	exitVal := m.Run()

	// make GC
	runtime.GC()
	time.Sleep(250 * time.Millisecond)
	runtime.GC()
	time.Sleep(250 * time.Millisecond)
	runtime.GC()
	// show memory after garbage collector
	runtime.ReadMemStats(after)
	beforeTotal = before.HeapAlloc
	afterTotal = after.HeapAlloc
	if beforeTotal != afterTotal {
		fmt.Print("memory usage increased during test! (", afterTotal-beforeTotal, ")\n")
	}
	return exitVal
}
func TestMain(m *testing.M) {
	exitVal := profileThis(m)
	os.Exit(exitVal)
}
