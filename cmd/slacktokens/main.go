// Command slacktokens prints the Slack workspace tokens and authentication
// cookies extracted from the desktop app's local storage as JSON.
//
//	slacktokens                # full Result: {"tokens":..., "cookie":..., "cookies":...}
//	slacktokens -tokens        # only the tokens map
//	slacktokens -cookie        # only the d cookie
//	slacktokens -cookies       # all auth cookies (d, d-s)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/hishamkaram/slacktokens"
)

func main() {
	var (
		tokensOnly  = flag.Bool("tokens", false, "print only the tokens map")
		cookieOnly  = flag.Bool("cookie", false, "print only the d cookie")
		cookiesOnly = flag.Bool("cookies", false, "print all auth cookies (d, d-s)")
	)
	flag.Parse()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	switch {
	case *tokensOnly:
		t, err := slacktokens.GetTokens()
		exitOn(err)
		exitOn(enc.Encode(t))
	case *cookieOnly:
		c, err := slacktokens.GetCookie()
		exitOn(err)
		exitOn(enc.Encode(c))
	case *cookiesOnly:
		c, err := slacktokens.GetCookies()
		exitOn(err)
		exitOn(enc.Encode(c))
	default:
		r, err := slacktokens.GetTokensAndCookie()
		exitOn(err)
		exitOn(enc.Encode(r))
	}
}

func exitOn(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "slacktokens:", err)
	os.Exit(1)
}
