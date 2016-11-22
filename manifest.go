package stretcher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/fujiwara/shapeio"
	"gopkg.in/yaml.v2"
)

var DefaultDestMode = os.FileMode(0755)

type Manifest struct {
	Src          string       `yaml:"src"`
	CheckSum     string       `yaml:"checksum"`
	Dest         string       `yaml:"dest"`
	DestMode     *os.FileMode `yaml:"dest_mode"`
	Commands     Commands     `yaml:"commands"`
	Excludes     []string     `yaml:"excludes"`
	ExcludeFrom  string       `yaml:"exclude_from"`
	SyncStrategy string       `yaml:"sync_strategy"`
}

type SrcFetch interface {
	fetch(tmp *os.File) error
}

type SrcFetcher struct {
	*Manifest
	MaxBandWidth uint64
}

type SrcFetcherEnableTimeout struct {
	*SrcFetcher
	Timeout time.Duration
}

func NewSrcFetcher(m *Manifest, conf Config) (SrcFetch, error) {
	s := &SrcFetcher{Manifest: m, MaxBandWidth: conf.MaxBandWidth}
	if conf.Timeout != 0 {
		st := &SrcFetcherEnableTimeout{SrcFetcher: s, Timeout: conf.Timeout}
		return st, nil
	}
	return s, nil
}

func (m *Manifest) newHash() (hash.Hash, error) {
	switch len(m.CheckSum) {
	case 32:
		return md5.New(), nil
	case 40:
		return sha1.New(), nil
	case 64:
		return sha256.New(), nil
	case 128:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("checksum must be md5, sha1, sha256, sha512 hex string.")
	}
}

func (m *Manifest) runCommands() error {
	if err := m.Commands.Pre.Invoke(); err != nil {
		return err
	}
	if err := m.Commands.Post.Invoke(); err != nil {
		return err
	}
	return nil
}

func (m *Manifest) Deploy(conf Config) error {
	if m.Src == "" {
		return m.runCommands()
	}

	strategy, err := NewSyncStrategy(m)
	if err != nil {
		return err
	}

	tmp, err := ioutil.TempFile(os.TempDir(), "stretcher")
	log.Println("tmpfile:", tmp.Name())
	if err != nil {
		return err
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	s, _ := NewSrcFetcher(m, conf)

	if err := s.fetch(tmp); err != nil {
		for i := 0; i < conf.Retry; i++ {
			log.Printf("%s", err)
			log.Printf("Try again. Waiting: %s", conf.RetryWait)
			time.Sleep(conf.RetryWait)

			tmp.Close()
			os.Remove(tmp.Name())
			tmp, err = ioutil.TempFile(os.TempDir(), "stretcher")
			log.Println("tmpfile:", tmp.Name())
			if err != nil {
				return err
			}
			defer tmp.Close()
			defer os.Remove(tmp.Name())

			err = s.fetch(tmp)
			if err == nil {
				break
			}
		}
		if err != nil {
			return err
		}
	}

	dir, err := ioutil.TempDir(os.TempDir(), "stretcher_src")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	err = m.Commands.Pre.Invoke()
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err = os.Chdir(dir); err != nil {
		return err
	}

	log.Println("Extract archive:", tmp.Name(), "to", dir)
	out, err := exec.Command("tar", "xf", tmp.Name()).CombinedOutput()
	if len(out) > 0 {
		log.Println(string(out))
	}
	if err != nil {
		log.Println("failed: tar xf", tmp.Name(), "failed", err)
		return err
	}

	log.Println("Set dest mode", *m.DestMode)
	err = os.Chmod(dir, *m.DestMode)
	if err != nil {
		return err
	}

	from := dir + "/"
	to := m.Dest

	err = strategy.Sync(from, to)
	if err != nil {
		return err
	}

	if err = os.Chdir(cwd); err != nil {
		return err
	}

	err = m.Commands.Post.Invoke()
	if err != nil {
		return err
	}
	return nil
}

func (st *SrcFetcherEnableTimeout) fetch(tmp *os.File) error {
	log.Printf("Set timeout %s", st.Timeout)

	timer := time.NewTimer(st.Timeout)
	done := make(chan error)
	go func() {
		s := st.SrcFetcher
		done <- s.fetch(tmp)
	}()
	select {
	case <-timer.C:
		return fmt.Errorf("timeout %s reached while fetching src %s", st.Timeout, st.Src)
	case err := <-done:
		return err
	}
}

func (s *SrcFetcher) fetch(tmp *os.File) error {
	begin := time.Now()
	src, err := getURL(s.Src)
	if err != nil {
		return fmt.Errorf("Get src failed: %s", err)
	}
	defer src.Close()

	lsrc := shapeio.NewReader(src)
	if s.MaxBandWidth != 0 {
		log.Printf("Set max bandwidth %s/sec", humanize.Bytes(uint64(s.MaxBandWidth)))
		lsrc.SetRateLimit(float64(s.MaxBandWidth))
	}

	m := s.Manifest
	written, sum, err := m.copyAndCalcHash(tmp, lsrc)
	if err != nil {
		return err
	}
	elapsed := time.Since(begin)
	log.Printf("Wrote %s bytes to %s (in %s, %s/s)",
		humanize.Comma(written),
		tmp.Name(),
		elapsed,
		humanize.Bytes(uint64(float64(written)/elapsed.Seconds())),
	)
	if len(m.CheckSum) > 0 && sum != strings.ToLower(m.CheckSum) {
		return fmt.Errorf("Checksum mismatch. expected:%s got:%s", m.CheckSum, sum)
	} else {
		log.Printf("Checksum ok: %s", sum)
	}
	return nil
}

func (m *Manifest) copyAndCalcHash(dst io.Writer, src io.Reader) (int64, string, error) {
	h, err := m.newHash()
	if err != nil {
		return 0, "", err
	}
	w := io.MultiWriter(h, dst)

	written, err := io.Copy(w, src)
	if err != nil {
		return written, "", err
	}
	s := fmt.Sprintf("%x", h.Sum(nil))
	return written, s, err
}

func ParseManifest(data []byte) (*Manifest, error) {
	m := &Manifest{}
	if err := yaml.Unmarshal(data, m); err != nil {
		return nil, err
	}
	if m.Src != "" && m.Dest == "" {
		return nil, fmt.Errorf("Dest is required")
	}
	if m.DestMode == nil {
		mode := DefaultDestMode
		m.DestMode = &mode
	}
	return m, nil
}
