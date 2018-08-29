package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"log"

	"github.com/coniks-sys/coniks-go/client"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
)

// ServerCmd represents the base "testclient" command when called without any
// subcommands (register, lookup, ...).
var ServerCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the CONIKS client as a local http server",
	Long:  "Run the CONIKS client as a local http server, transferring the requests to the CONIKS Server",
	Run: func(cmd *cobra.Command, args []string) {
		startLocalHTTPServer(cmd)
	},
}

var allowedOrigins = []string{"127\\.0\\.0\\.1", "localhost", "dev\\.coedit\\.re", "coedit\\.re"}

func init() {
	RootCmd.AddCommand(ServerCmd)
	ServerCmd.Flags().StringP("config", "c", "config.toml",
		"Config file for the client (contains the server's initial public key etc).")
}

func startLocalHTTPServer(cmd *cobra.Command) {
	conf := loadConfigOrExit(cmd)
	if conf.ServerAddress == nil {
		log.Fatal("Wrong config ! server-address is not specified in the config.toml.")
	}
	http.HandleFunc("/", makeHandler(conf))
	address := conf.ServerAddress.Address
	certPath, keyPath := conf.ServerAddress.TLSCertPath, conf.ServerAddress.TLSKeyPath
	log.Printf("Listening on %v\n", address)
	err := http.ListenAndServeTLS(address, certPath, keyPath, nil)
	if err != nil {
		log.Fatalln(err)
	}
}

func makeHandler(conf *client.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		setHeaders(&w, r)
		if r.Method == "OPTIONS" {
			return
		}
		body, _ := ioutil.ReadAll(r.Body)
		bodyStr := string(body)
		log.Printf("Received request : %s\n", bodyStr)
		bearer := r.Header.Get("Authorization")
		cc := p.NewCC(nil, true, conf.SigningPubKey)
		args := strings.Fields(bodyStr)
		if len(args) < 1 {
			msg := "[!] Usage :\n\nregister <name> <key>\nor\nlookup <name>"
			log.Print(msg)
			http.Error(w, fmt.Sprint(msg), http.StatusBadRequest)
			return
		}
		cmd := args[0]
		switch cmd {
		case "register":
			if len(args) != 3 {
				msg := "[!] Incorrect number of args to register.\nUsage : register <name> <key>"
				log.Printf(msg)
				http.Error(w, fmt.Sprint(msg), http.StatusBadRequest)
				return
			}
			msg, errCode := register(cc, conf, args[1], args[2], bearer)
			httpErrorCode := errorCodeToHTTPError(errCode)
			log.Printf("[+] Coniks protocol error code: %d - corresponding HTTP error code: %d - %s", errCode, httpErrorCode, msg)
			http.Error(w, fmt.Sprintf("[+] %s", msg), httpErrorCode)
		case "lookup":
			if len(args) != 2 {
				msg := "[!] Incorrect number of args to lookup.\nUsage : lookup <name>"
				log.Printf(msg)
				http.Error(w, fmt.Sprint(msg), http.StatusBadRequest)
				return
			}
			msg, errCode := keyLookup(cc, conf, args[1], bearer)
			httpErrorCode := errorCodeToHTTPError(errCode)
			log.Printf("[+] Coniks protocol error code: %d - corresponding HTTP error code: %d - %s", errCode, httpErrorCode, msg)
			http.Error(w, fmt.Sprintf("[+] %s", msg), httpErrorCode)
		default:
			log.Printf("[!] Unrecognized command: %s", cmd)
			http.Error(w, fmt.Sprintf("[!] Unrecognized command: %s", cmd), http.StatusBadRequest)
		}
	}
}

// Transform a CONIKS protocol error code into HTTP Error code
// Success -> 200
// NameNotFound -> 404 Not Found
// NameAlreadyExists -> 409 Conflict
// CheckBadSTR -> 500 Internal Server error
// Other internal errors -> 500 Internal Server error
func errorCodeToHTTPError(errCode p.ErrorCode) int {
	var httpError int
	switch errCode {
	case p.ReqNameNotFound:
		httpError = http.StatusNotFound
	case p.ReqNameExisted:
		httpError = http.StatusConflict
	case p.ReqSuccess:
		httpError = http.StatusOK
	case p.CheckBadSTR, 500:
		httpError = http.StatusInternalServerError
	default:
		httpError = http.StatusInternalServerError
	}
	return httpError
}

func isOriginAllowed(origin string) bool {
	allowedOriginsJoined := strings.Join(allowedOrigins, "|")
	var pattern = regexp.MustCompile(fmt.Sprintf(`(https?:\/\/)(%s)(:[0-9]+)?`, allowedOriginsJoined))

	return pattern.MatchString(origin)
}

func setHeaders(w *http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if isOriginAllowed(origin) {
		log.Printf("Origin %s allowed\n", origin)
		(*w).Header().Set("Access-Control-Allow-Origin", origin)
		(*w).Header().Set("Access-Control-Allow-Headers", "Authorization")
		(*w).Header().Add("Vary", "Origin")
		(*w).Header().Add("Vary", "Access-Control-Request-Method")
		(*w).Header().Add("Vary", "Access-Control-Request-Headers")
	} else {
		log.Printf("Origin %s not allowed\n", origin)
	}
}
