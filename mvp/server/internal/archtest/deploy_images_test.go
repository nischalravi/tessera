package archtest

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	digestRE    = regexp.MustCompile(`@sha256:[0-9a-f]{64}\b`)
	composeImg  = regexp.MustCompile(`^\s*image:\s*(\S+)`)
	dockerARG   = regexp.MustCompile(`^ARG\s+[A-Z_]*IMAGE=(\S+)`)
	dockerFROM  = regexp.MustCompile(`(?i)^FROM\s+(?:--\S+\s+)*(\S+)`)
	latestTagRE = regexp.MustCompile(`:latest(\s|$|"|@)`)
)

// TestDeploy_ThirdPartyImagesPinnedByDigest rejects mutable third-party base images under deploy/ (issue #530):
// every image in the Dockerfile and in the Compose file must carry an @sha256 digest, and ":latest" is banned
// in any manifest. Images Tessera builds itself (tessera-*, ${VAR} placeholders and stage names) are exempt.
func TestDeploy_ThirdPartyImagesPinnedByDigest(t *testing.T) {
	deploy := filepath.Join(moduleRoot(t), "..", "..", "deploy")
	if _, err := os.Stat(deploy); err != nil {
		t.Skip("deploy/ not present")
	}
	exempt := func(img string) bool {
		return strings.HasPrefix(img, "${") && strings.Contains(img, "tessera-") || strings.Contains(img, "/tessera-") || strings.HasPrefix(img, "tessera-")
	}
	check := func(path string, re *regexp.Regexp, stages map[string]bool) {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			img := strings.Trim(m[1], `"'`)
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM") && (stages[img] || strings.HasPrefix(img, "${") || img == "scratch") {
				continue
			}
			if exempt(img) || digestRE.MatchString(img) {
				continue
			}
			t.Errorf("%s:%d: image %q is not pinned by @sha256 digest", path, n, img)
		}
	}
	check(filepath.Join(deploy, "compose", "docker-compose.yml"), composeImg, nil)
	check(filepath.Join(deploy, "docker", "Dockerfile"), dockerARG, nil)
	check(filepath.Join(deploy, "docker", "Dockerfile"), dockerFROM, map[string]bool{"base": true, "gobuild": true, "uibuild": true, "api": true, "cli": true, "init": true})

	err := filepath.WalkDir(deploy, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(p); ext != ".yml" && ext != ".yaml" && ext != ".json" && filepath.Base(p) != "Dockerfile" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(b), "\n") {
			if m := composeImg.FindStringSubmatch(line); m != nil && latestTagRE.MatchString(m[1]+" ") && !exempt(m[1]) {
				t.Errorf("%s:%d: %q uses the mutable :latest tag", p, n+1, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
