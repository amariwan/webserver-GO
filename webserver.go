package webserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-http-utils/cors"
	"gitmaster.hq.aland-mariwan.de/go/cert.git"
	"gitmaster.hq.aland-mariwan.de/go/logger.git"
	"gitmaster.hq.aland-mariwan.de/go/sessionstore.git"
)

// WebServerConfig allows to pass configuration parameters
type WebServerConfig struct {
	Secure       bool   `json:"secure"`       //true for use of ssl
	SslCertsPath string `json:"sslCertsPath"` // path to certs
	Address      string `json:"address"`      // bind address
	Port         int    `json:"port"`         // listen port
}

// SessionChecker is an interface to the session store or a data token validation/extraction provider
// if a session store is used, the token is a key into the session store
// if JWT (json web token) is used, the token contains the session state, see
// https://de.wikipedia.org/wiki/JSON_Web_Token nad github.com/dgrijalva/jwt-go
type SessionChecker interface {
	// NewSessionToken generates a preliminary token for early use (e.g. at login)
	NewSessionToken() string
	// CheckSession tests session identified by token and returns info about the session or error
	CheckSession(token string) (usrData interface{}, expiry time.Time, err error)
	// CheckSession tests session identified by token and returns info about the session or error
	RenewSession(token string) (newToken string, usrData interface{}, expiry time.Time, err error)
	// BeginSession opens a new session and returns the new session token
	BeginSession(c *Credentials, data interface{}, predefinedToken string) (token string, expiry time.Time)
}

// Credentials is used to pass login information (either user/pass or apiKey)
type Credentials struct {
	User       string
	Password   string
	ApiKey     string
	RemoteAddr string
	AuthType   string
        Tenant     string
}

// LoginChecker is an interface to the Login provider (user database access)
type LoginChecker interface {
	// Login uses credentials to authenticate user and returns user data, session enable flag and error
	// if usrData is returned but createSession is false, only pass the current request but do not create a session
	Login(c *Credentials, token string) (usrData sessionstore.SessionUserData, errorResponse http.Handler, err error)
	CredentialsFromBodyExtractor(body []byte) (c Credentials)
}

// WebServer instance and config struct
type WebServer struct {
	ctx         context.Context
	srv         http.Server
	stop        chan int
	done        sync.WaitGroup
	certManager *cert.Manager
	WebServerConfig
	sessionstore        *sessionstore.SessionStore
	exiting             bool
	createCertIfMissing bool
	certNamePrefix      string
	certNameSuffix      string
	data                interface{}
	sessionChecker      SessionChecker
	loginChecker        LoginChecker
	cookieName          string
}

// cookieName contains the default session token name
const cookieName = "oms.sid"

// contextKey is a type for a key to store information in the context
type contextKey string

// contextKeyValye is the key to store information in the context
const contextKeyValue contextKey = "gitmaster.hq.aland-mariwan.de/go/webserver"

// New creates a web server instance
// cfg contains configuration data
// contextKey contains the key to store the context data
func New(cfg WebServerConfig, data interface{}, sessionCloser func(sessionstore.SessionUserData)) *WebServer {
	ws := WebServer{WebServerConfig: cfg}
	ws.sessionstore = sessionstore.New(sessionCloser)
	ws.data = data
	ws.certNamePrefix = "tls"
	ws.certNameSuffix = ""
	ws.ctx = context.WithValue(context.Background(), contextKeyValue, ws)
	ws.stop = make(chan int, 1)
	ws.cookieName = cookieName
	ws.sessionChecker = &ws // default implementation, ok for most use cases
	ws.loginChecker = &ws   // default implementation, not OK - passes rolf/geheim only
	return &ws
}

// adjust session timeout
func (ws *WebServer) SetSessionTimeout(expiry time.Duration) {
	ws.sessionstore.SetSessionTimeout(expiry)
}

// CreateCertIfMissing set the property that controls if a new certificate should be created if none is found
func (ws *WebServer) CreateCertIfMissing() bool {
	old := ws.createCertIfMissing
	ws.createCertIfMissing = true
	return old
}

// SetCertNamePattern sets the base name of certificate files (default tls)
func (ws *WebServer) SetCertNamePattern(prefix string, suffix string) (string, string) {
	oldprefix := ws.certNamePrefix
	oldsuffix := ws.certNameSuffix
	ws.certNamePrefix = prefix
	ws.certNameSuffix = suffix
	return oldprefix, oldsuffix
}

// ContextGetData reads a value from the context map
func ContextGetData(ctx context.Context) interface{} {
	return ctx.Value(contextKeyValue)
}

var ErrWebSrvNull = errors.New("webserver object is nil")
var ErrWebSrvLogin = errors.New("no valid credentials found")
var ErrWebSrvUnsupported = errors.New("unsupported Authorization method")
var ErrWebSrvSession = errors.New("no valid session token found")

// GetRequestCredentials reads user/password or API key from a http request
// get user password from either URL (user:password@host/path), URL parameters (user, password) or HTTP Basic Auth
// get API Key from either URL parameter (key) or HTTP header x-auth-key
// if user/password is found, key is ignored
func (ws *WebServer) GetRequestCredentials(r *http.Request) (*Credentials, error) {
	v := Credentials{RemoteAddr: r.RemoteAddr}
	u, err := url.Parse(r.RequestURI)
	if err != nil {
		logger.Errorf("login failed, invalid URI")
		return &v, err
	}

	if u.User != nil { // url had user/password field - only on requestor side
		v.User = u.User.Username()
		var present bool = false
		v.Password, present = u.User.Password()
		if present {
			return &v, nil
		}
	}
	// check URL parameters user/password
	params, _ := url.ParseQuery(u.RawQuery)
	user := params["user"]
	password := params["password"]
        tenant := params["tenant"]
	key := params["key"]
        if tenant != nil {
        	v.Tenant = tenant[0]
        }
	if user != nil && password != nil {
		v.User = user[0]
		v.Password = password[0]
		if key != nil {
			v.ApiKey = key[0] // set api key if present
		}
		return &v, nil
	}
	// check authorization header
	authHdrs := r.Header["Authorization"]
	for _, authHdr := range authHdrs {
		fields := strings.Split(authHdr, " ")
		if strings.EqualFold(fields[0], "Basic") {
			b64 := strings.Trim(fields[1], "=")
			b, err := base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				logger.Errorf("user/password login failed (from Authorization header)")
				return &v, err
			}
			s := strings.Split(string(b), ":")
			v.User = s[0]
			v.Password = s[1]
			return &v, nil
			/* } else if strings.EqualFold(fields[0], "Bearer") { // use bearer only for tokens, not for API key
			v.apiKey = fields[1]
			return &v, nil */
		} else {
			logger.Errorf("login failed, auth method %s not supported", authHdrs[0])
			return &v, ErrWebSrvUnsupported
		}
	}
	// no auth headers, check for API key
	authHdrs = r.Header["X-Auth-Key"]
	if authHdrs != nil {
		v.ApiKey = authHdrs[0]
		return &v, nil
	}
	// check key URL parameter
	if key != nil {
		v.ApiKey = key[0]
		return &v, nil
	}
	if ws.loginChecker != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Errorf("login failed, could not read body: %v", err)
			return &v, ErrWebSrvLogin
		}
		v = ws.loginChecker.CredentialsFromBodyExtractor(body)
		v.RemoteAddr = r.RemoteAddr // need to update this field here
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		return &v, nil
	}
	// no credentials, try to read session key (cookie or X-Session-Token)
	logger.Errorf("login failed, no valid credentials found")
	return &v, ErrWebSrvLogin
}

// GetSessionToken extracts a session token from either http headers or cookies
// check cookie with specified name or (if not set) use Authorization header with bearer type
func GetSessionToken(cookies []*http.Cookie, h *http.Header, cookieName string) (string, error) {
	var sessionToken string = ""
	for _, c := range cookies {
		if c.Name == cookieName {
			sessionToken = c.Value
			break
		}
	}
	if sessionToken == "" {
		authorizationHeader := h.Get("Authorization")
		if authorizationHeader != "" {
			headerParts := strings.Split(authorizationHeader, " ")
			if len(headerParts) == 2 && strings.ToLower(headerParts[0]) == "bearer" {
				sessionToken = headerParts[1]
			}
		}
	}
	if sessionToken == "" {
		logger.Errorf("no valid session token found")
		return "", ErrWebSrvSession
	}
	return sessionToken, nil
}

type WebServerKey string

const keyUserData WebServerKey = "UserData"
const keySessionToken WebServerKey = "SessionToken"

func setContextValues(ctx context.Context, data interface{}, token string) context.Context {
	ctx = context.WithValue(ctx, keyUserData, data)
	ctx = context.WithValue(ctx, keySessionToken, token)
	return ctx
}

// HttpSessionChecker will chain in a http handler to provide session token checks
func (ws *WebServer) HttpSessionChecker(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := GetSessionToken(r.Cookies(), &r.Header, ws.cookieName)
		if err != nil {
			logger.Errorf("no session token found")
			http.Error(w, "no authentication token present", http.StatusUnauthorized)
			return
		}
		newToken, sessionData, _, err := ws.sessionChecker.RenewSession(token)
		if err != nil {
			logger.Errorf("%s '%s'", "Authentication using session token failed with", err.Error())
			http.Error(w, "no authentication token present", http.StatusUnauthorized)
			return
		}
		w.Header().Add("session-token", newToken)
		w.Header().Set("set-cookie", ws.cookieName+"="+newToken+"; Path=/; SameSite=None; Secure")
		// save user data and token in context
		h.ServeHTTP(w, r.WithContext(setContextValues(r.Context(), sessionData, newToken)))
	})
}

// HttpLoginChecker will chain in a http handler to provide login checks
func (ws *WebServer) HttpLoginChecker(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ws.loginChecker == nil || ws.sessionChecker == nil {
			logger.Error("Authentication failed - no login backend set")
			http.Error(w, "login failed, internal error", http.StatusInternalServerError)
			return
		}
		credentials, err := ws.GetRequestCredentials(r)
		if err != nil {
			logger.Errorf("%s '%s'", "no credentials in request, trying http authentication", err.Error())
			w.Header().Add("WWW-Authenticate", "Basic realm=\"access to the staging site\"")
			http.Error(w, "no login credentials present", http.StatusUnauthorized)
			return
		}
		token := ws.sessionChecker.NewSessionToken()
		sessionData, errHandler, err := ws.loginChecker.Login(credentials, token)
		if err != nil {
			if errHandler != nil {
				errHandler.ServeHTTP(w, r)
				return
			} else {
				logger.Errorf("%s '%s' %s: %s", "Authentication for", credentials.User, "failed", err.Error())
				http.Error(w, "Authentication failed", http.StatusForbidden)
			}
			return
		}
		token, _ = ws.sessionChecker.BeginSession(credentials, sessionData, token)

		w.Header().Add("session-token", token)
		w.Header().Set("set-cookie", ws.cookieName+"="+token+"; Path=/; SameSite=None; Secure")
		// save user data and token in context
		h.ServeHTTP(w, r.WithContext(setContextValues(r.Context(), sessionData, token)))
	})
}

// GetSessionTokenFromRequestContext reads the session token from the request context.
func GetSessionTokenFromRequestContext(r *http.Request) string {
	if m := r.Context().Value(keySessionToken); m != nil {
		if value, ok := m.(string); ok {
			return value
		}
	}
	return ""
}

// GetUserDataFromRequestContext reads the user data object from the request context.
func GetUserDataFromRequestContext(r *http.Request) interface{} {
	if m := r.Context().Value(keyUserData); m != nil {
		return m
	}
	return nil
}

// SetCookieName sets the cookie name property and returns the old setting
func (ws *WebServer) SetCookieName(name string) string {
	old := ws.cookieName
	ws.cookieName = name
	return old
}

// SetLoginChecker sets the login helper and returns the old setting
func (ws *WebServer) SetLoginChecker(login LoginChecker) LoginChecker {
	old := ws.loginChecker
	ws.loginChecker = login
	return old
}

// SetSessionChecker sets the session helper and returns the old setting
func (ws *WebServer) SetSessionChecker(check SessionChecker) SessionChecker {
	old := ws.sessionChecker
	ws.sessionChecker = check
	return old
}

// Run runs the web server
// mux: pass in a http handler to call for all routes (use mux in application code if needed)
// https://medium.com/@matryer/the-http-handler-wrapper-technique-in-golang-updated-bc7fbcffa702
// corsOptions: options that influence CORS behaviour
func (ws *WebServer) Run(mux *http.ServeMux, corsOptions ...cors.Option) error {
	err := ws.initServer(mux, corsOptions...)
	if err != nil {
		logger.Errorf("webserver initServer failed: %s", err)
		return err
	}
	ws.done.Add(1)
	ws.exiting = false
	go func() {
		defer ws.done.Done()
		logger.Info("running HTTP server on " + ws.srv.Addr)
		if ws.Secure {
			if err := ws.srv.ListenAndServeTLS("", ""); !ws.exiting && (err != nil) {
				if err != http.ErrServerClosed {
					logger.Error(err)
				}
			}
		} else {
			if err := ws.srv.ListenAndServe(); !ws.exiting && (err != nil) {
				logger.Error(err)
			}
		}
		logger.Info("HTTP server on " + ws.srv.Addr + " stopped")
		ws.stop <- 1
		logger.Info("HTTP server on " + ws.srv.Addr + " stopped")
	}()
	return nil
}

// Close will shut down the web server
func (ws *WebServer) Close() error {
	if ws == nil {
		return ErrWebSrvNull
	}
	if ws.certManager != nil {
		ws.certManager.Close()
	}
	ws.exiting = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logger.Info("Shutting down HTTP server")
	if err := ws.srv.Shutdown(ctx); err != nil {
		logger.Error(err)
		return err
	}

	// Wait for ListenAndServe goroutine to close.
	ws.done.Wait()
	logger.Info("HTTP server exited")
	ws.sessionstore.Close()
	return nil
}

// GetHttpServer Get underlying http server
func (ws *WebServer) GetHttpServer() *http.Server {
	return &ws.srv
}

// GetCertManager Get underlying certificate manager
func (ws *WebServer) GetCertManager() *cert.Manager {
	return ws.certManager
}

// webserverContext is a a getter for the context of the WebServer
func (ws *WebServer) webserverContext(listener net.Listener) context.Context {
	return ws.ctx
}

// initServer performs the initialization of the web server instance
func (ws *WebServer) initServer(mux *http.ServeMux, corsOptions ...cors.Option) error {
	if ws.Secure {
		privateKeyPath := filepath.Join(ws.SslCertsPath, ws.certNamePrefix+".key"+ws.certNameSuffix)
		certificatePath := filepath.Join(ws.SslCertsPath, ws.certNamePrefix+".crt"+ws.certNameSuffix)
		csrPath := filepath.Join(ws.SslCertsPath, ws.certNamePrefix+".csr"+ws.certNameSuffix)

		var err error
		ws.certManager, err = cert.New(certificatePath, privateKeyPath, csrPath, "",
			time.Duration(time.Hour*24*390), true, 4096, ws.createCertIfMissing)
		if err != nil {
			logger.Error("Could not create certificate manager: ", err)
			return err
		}

		cfg := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			GetCertificate: ws.certManager.GetCertificate,
		}
		ws.srv = http.Server{
			Addr:         ws.Address + ":" + strconv.Itoa(ws.Port),
			Handler:      cors.Handler(mux, corsOptions...),
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			BaseContext:  ws.webserverContext,
		}
	} else {
		ws.srv = http.Server{
			Addr:        ws.Address + ":" + strconv.Itoa(ws.Port),
			Handler:     cors.Handler(mux, corsOptions...),
			BaseContext: ws.webserverContext,
		}
	}
	return nil
}

// WaitForCtrlC waits for Ctrl-C from the console - this could be used to stop a web server
func (ws *WebServer) WaitForCtrlC(c chan struct{}) {
	signal_channel := make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	select {
	case <-signal_channel:
	case <-c:
	case <-ws.stop:
	}
	signal.Stop(signal_channel)
	close(signal_channel)
}

func CloseBody(r *http.Request) {
	var buf []byte
	r.Body.Read(buf)
	r.Body.Close()
}

// NewSessionSession starts a new session for the already authenticated user and returns token and expiry
func (ws *WebServer) NewSessionToken() string {
	return ws.sessionstore.NewSessionToken()
}

// BeginSession starts a new session for the already authenticated user and returns token and expiry
func (ws *WebServer) BeginSession(c *Credentials, data interface{}, predefinedToken string) (string, time.Time) {
	return ws.sessionstore.BeginSession(predefinedToken, data)
}

// CheckSession checks token and returns data of session if valid
func (ws *WebServer) CheckSession(token string) (usrData interface{}, expiry time.Time, err error) {
	return ws.sessionstore.CheckSession(token, usrData)
}

// CheckSession checks token and returns data of session if valid
func (ws *WebServer) RenewSession(token string) (newToken string, usrData interface{}, expiry time.Time, err error) {
	return ws.sessionstore.RenewSession(token, usrData)
}

// EndSession closes the session identified by token
func (ws *WebServer) EndSession(token string) bool {
	return ws.sessionstore.EndSession(token)
}

// Login is a default implementation for the loginChecker interface, do not use this implementation but overload!
// A proper implementation would access a user data base and retrieve user data from it
func (ws *WebServer) Login(c *Credentials, token string) (usrData sessionstore.SessionUserData, errorResponse http.Handler, err error) {
	if c.User == "rolf" && c.Password == "geheim" {
		return c, nil, nil
	} else {
		return nil, nil, errors.New("login failed")
	}
}

// CredentialsFromBodyExtractor is an empty default implementation for the loginChecker interface
// it will return an empty credential struct
func (ws *WebServer) CredentialsFromBodyExtractor(body []byte) (c Credentials) {
	return Credentials{}
}
