package unixssh

import "golang.org/x/crypto/ssh"

// passwordAuth is the sign-in of a connector built with Config.Password. It exists for the SFTP
// contractor feed (issue #961) and lives in its own file so the rule "no password sign-in" stays
// checkable everywhere else (TestNoInsecureHostKeyOutsideTests). The commands of Read stay key-only:
// Read refuses a connector that has no key.
func (c *Connector) passwordAuth() ssh.AuthMethod { return ssh.Password(c.cfg.Password.Reveal()) }
