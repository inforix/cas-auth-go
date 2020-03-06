package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/securecookie"

	cas "github.com/inforix/cas-client-go"
)

var (
	nsCookieName         = "NSLOGIN"
	nsCookieHashKey      = []byte("SECURE_COOKIE_HASH_KEY")
	nsRedirectCookieName = "NSREDIRECT"
)

type myHandler struct{}
type loginHandler struct{}
type logoutHandler struct{}
type authHandler struct{}

// MyHandler not comment
var MyHandler = &myHandler{}

var casURL string
var port int

func init() {
	flag.StringVar(&casURL, "url", "https://cas.shmtu.edu.cn/cas", "CAS server URL")
	flag.IntVar(&port, "port", 8080, "listen port, default is 8080")
}

func main() {
	flag.Parse()

	if casURL == "" {
		flag.Usage()
		return
	}

	glog.Info("Starting up, listen Port: ", port, " CAS: ", casURL)

	m := http.NewServeMux()
	m.Handle("/", MyHandler)
	m.Handle("/auth", new(authHandler))
	m.Handle("/login", new(loginHandler))
	m.Handle("/logout", new(logoutHandler))

	url, _ := url.Parse(casURL)
	client := cas.NewClient(&cas.Options{
		URL: url,
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: client.Handle(m),
	}

	if err := server.ListenAndServe(); err != nil {
		glog.Infof("Error from HTTP Server: %v", err)
	}

	glog.Info("Shutting down")
}

type templateBinding struct {
	Username   string
	Attributes cas.UserAttributes
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	glog.Info("Enter Auth")
	
	if !cas.IsAuthenticated(r) {
		glog.Info("Not Authroized, return 401")
	        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	        return
	}
	var s = securecookie.New(nsCookieHashKey, nil)
	// get the cookie from the request
	if cookie, err := r.Cookie(nsCookieName); err == nil {
		value := make(map[string]string)
		// try to decode it
		if err = s.Decode(nsCookieName, cookie.Value, &value); err == nil {
			glog.Info("Decode cookie")
			glog.Info(value["user"])
			w.Header().Add("X-Forwarded-User", value["user"])
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	glog.Info("return 401")
	// Otherwise, return HTTP 401 status code
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	glog.Info("Enter loginHandler...")

	if !cas.IsAuthenticated(r) {
		glog.Info("Redirect to CAS Login...")
		cas.RedirectToLogin(w, r)
		return
	}

	glog.Info("CAS Already logged in")
	var s = securecookie.New(nsCookieHashKey, nil)
	value := map[string]string{
		"user": cas.Username(r),
	}

	if encoded, err := s.Encode(nsCookieName, value); err == nil {
		cookie := &http.Cookie{
			Name:    nsCookieName,
			Value:   encoded,
			Domain:  ".shmtu.edu.cn",
			Expires: time.Now().AddDate(1, 0, 0),
			Path:    "/",
		}
		http.SetCookie(w, cookie)
	}

	var redirectURL = "/"
	if cookie, err := r.Cookie(nsRedirectCookieName); err == nil {
		redirectURL = cookie.Value
	}

	glog.Info("redirectURL: ", redirectURL)

	// ... and delete the original destination holder cookie
	http.SetCookie(w, &http.Cookie{
		Name:    nsRedirectCookieName,
		Value:   "deleted",
		Domain:  ".shmtu.edu.cn",
		Expires: time.Now().Add(time.Hour * -24),
		Path:    "/",
	})

	http.Redirect(w, r, redirectURL, http.StatusFound)

	w.Write([]byte("No return URL specified"))
}

func (h *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	glog.Info("Enter logoutHandler...")

	http.SetCookie(w, &http.Cookie{
		Name:    nsCookieName,
		Value:   "deleted",
		Domain:  ".shmtu.edu.cn",
		Expires: time.Now().Add(time.Hour * -24),
		Path:    "/",
	})

	glog.Info("Leaving logoutHandler.")
	cas.RedirectToLogout(w, r)
}

func (h *myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !cas.IsAuthenticated(r) {
		cas.RedirectToLogin(w, r)
		return
	}

	w.Header().Add("Content-Type", "text/html")

	tmpl, err := template.New("index.html").Parse(indexHTML)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, error500, err)
		return
	}

	binding := &templateBinding{
		Username:   cas.Username(r),
		Attributes: cas.Attributes(r),
	}

	html := new(bytes.Buffer)
	if err := tmpl.Execute(html, binding); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, error500, err)
		return
	}

	html.WriteTo(w)
}

const indexHTML = `<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>Welcome {{.Username}}</title>
  </head>
  <body>
    <h1>Welcome {{.Username}} <a href="/logout">Logout</a></h1>
    <p>Your attributes are:</p>
    <ul>{{range $key, $values := .Attributes}}
      <li>{{$len := len $values}}{{$key}}:{{if gt $len 1}}
        <ul>{{range $values}}
          <li>{{.}}</li>{{end}}
        </ul>
      {{else}} {{index $values 0}}{{end}}</li>{{end}}
    </ul>
  </body>
</html>
`

const error500 = `<!DOCTYPE html>
<html>
  <head>
    <title>Error 500</title>
  </head>
  <body>
    <h1>Error 500</h1>
    <p>%v</p>
  </body>
</html>`
