// Package slacktokens extracts personal Slack workspace tokens and the
// authentication cookies (`d`, `d-s`) from the Slack desktop application's
// local storage.
//
// It is a Go port of github.com/hraftery/slacktokens (Python, GPLv3) and is
// itself distributed under GPLv3.
//
// Supported platforms: macOS and Linux. Windows is not supported.
//
// Slack must be quit before calling these functions; the LevelDB store is
// locked while the app is running.
//
// Example:
//
//	res, err := slacktokens.GetTokensAndCookie()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for url, ws := range res.Tokens {
//	    fmt.Printf("%s -> %s\n", url, ws.Token)
//	}
package slacktokens
