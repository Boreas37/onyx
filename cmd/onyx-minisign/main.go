// Command onyx-minisign generates onyx minisign keypairs and signs files
// with them. Signatures are minisign/signify-compatible Ed25519 detached
// signatures; the public keys verify both with this tool and with the
// onyx client's database verification ($ONYX_DB_PUBKEY).
//
// Usage:
//
//	onyx-minisign genkey -p onyx.pub -s onyx.sec [-c "comment"]
//	onyx-minisign sign   -s onyx.sec -m file          (writes file's .minisig)
//	onyx-minisign verify -p onyx.pub -S sig -m file
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Boreas37/onyx/internal/dbupdate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "genkey":
		fs := flag.NewFlagSet("genkey", flag.ExitOnError)
		pub := fs.String("p", "onyx.pub", "public key output path")
		sec := fs.String("s", "", "secret key output path (default: alongside -p)")
		comment := fs.String("c", "", "key comment")
		_ = fs.Parse(os.Args[2:]) // ExitOnError flag sets: never returns an error
		dir := "."
		wantPub, wantSec := *pub, *sec
		if wantSec == "" {
			wantSec = dir + "/" + "onyx.sec"
		}
		gotPub, gotSec, err := dbupdate.GenerateKeypair(dir, *comment)
		if err != nil {
			fatal(err)
		}
		if gotPub != wantPub || gotSec != wantSec {
			if rErr := os.Rename(gotPub, wantPub); rErr != nil {
				fatal(rErr)
			}
			if rErr := os.Rename(gotSec, wantSec); rErr != nil {
				fatal(rErr)
			}
		}
		fmt.Printf("public key:  %s\nsecret key:  %s\n", wantPub, wantSec)

	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		sec := fs.String("s", "onyx.sec", "secret key path")
		msg := fs.String("m", "", "file to sign")
		_ = fs.Parse(os.Args[2:]) // ExitOnError flag sets: never returns an error
		if *msg == "" {
			fatal(fmt.Errorf("sign needs -m FILE"))
		}
		sigPath, err := dbupdate.Sign(*sec, *msg)
		if err != nil {
			fatal(err)
		}
		fmt.Println(sigPath)

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		pub := fs.String("p", "onyx.pub", "public key path")
		sig := fs.String("S", "", "signature path")
		msg := fs.String("m", "", "signed file")
		_ = fs.Parse(os.Args[2:]) // ExitOnError flag sets: never returns an error
		if *sig == "" || *msg == "" {
			fatal(fmt.Errorf("verify needs -S SIG and -m FILE"))
		}
		if err := dbupdate.VerifyMinisign(*pub, *sig, *msg); err != nil {
			fatal(err)
		}
		fmt.Printf("signature OK: %s\n", *msg)

	default:
		usage()
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "onyx-minisign:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  onyx-minisign genkey -p PUB -s SEC [-c COMMENT]
  onyx-minisign sign   -s SEC -m FILE
  onyx-minisign verify -p PUB -S SIG -m FILE`)
}
