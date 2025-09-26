package ffuf

import (
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
)

// used for random string generation in calibration function
var chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// RandomString returns a random string of length of parameter n
func RandomString(n int) string {
	s := make([]rune, n)
	for i := range s {
		s[i] = chars[rand.Intn(len(chars))]
	}
	return string(s)
}

// UniqStringSlice returns an unordered slice of unique strings. The duplicates are dropped
func UniqStringSlice(inslice []string) []string {
	found := map[string]bool{}

	for _, v := range inslice {
		found[v] = true
	}
	ret := []string{}
	for k := range found {
		ret = append(ret, k)
	}
	return ret
}

// FileExists checks if the filepath exists and is not a directory.
// Returns false in case it's not possible to describe the named file.
func FileExists(path string) bool {
	md, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !md.IsDir()
}

// RequestContainsKeyword checks if a keyword is present in any field of a request
func RequestContainsKeyword(req Request, kw string) bool {
	if strings.Contains(req.Host, kw) {
		return true
	}
	if strings.Contains(req.Url, kw) {
		return true
	}
	if strings.Contains(req.Method, kw) {
		return true
	}
	if strings.Contains(string(req.Data), kw) {
		return true
	}
	for k, v := range req.Headers {
		if strings.Contains(k, kw) || strings.Contains(v, kw) {
			return true
		}
	}
	return false
}

// HostURLFromRequest gets a host + path without the filename or last part of the URL path
func HostURLFromRequest(req Request) string {
	u, _ := url.Parse(req.Url)
	u.Host = req.Host
	pathparts := strings.Split(u.Path, "/")
	trimpath := strings.TrimSpace(strings.Join(pathparts[:len(pathparts)-1], "/"))
	return u.Host + trimpath
}

// Version returns the ffuf version string
func Version() string {
	return fmt.Sprintf("%s%s", VERSION, VERSION_APPENDIX)
}

// CheckOrCreateConfigDir 检查并创建所有必要的配置目录
// 该函数会依次创建配置目录、历史记录目录、爬虫目录和自动校准目录，
// 并设置默认的自动校准策略
//
// 返回值:
//
//	error - 如果在创建目录或设置策略过程中发生错误则返回相应错误，否则返回nil
func CheckOrCreateConfigDir() error {
	var err error

	// 创建主配置目录
	err = createConfigDir(CONFIGDIR)
	if err != nil {
		return err
	}

	// 创建历史记录目录
	err = createConfigDir(HISTORYDIR)
	if err != nil {
		return err
	}

	// 创建爬虫相关目录
	err = createConfigDir(SCRAPERDIR)
	if err != nil {
		return err
	}

	// 创建自动校准目录
	err = createConfigDir(AUTOCALIBDIR)
	if err != nil {
		return err
	}

	// 设置默认的自动校准策略
	err = setupDefaultAutocalibrationStrategies()
	return err
}

func createConfigDir(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		var pError *os.PathError
		if errors.As(err, &pError) {
			return os.MkdirAll(path, 0750)
		}
		return err
	}
	return nil
}

func StrInSlice(key string, slice []string) bool {
	for _, v := range slice {
		if v == key {
			return true
		}
	}
	return false
}

func mergeMaps(m1 map[string][]string, m2 map[string][]string) map[string][]string {
	merged := make(map[string][]string)
	for k, v := range m1 {
		merged[k] = v
	}
	for key, value := range m2 {
		if _, ok := merged[key]; !ok {
			// Key not found, add it
			merged[key] = value
			continue
		}
		for _, entry := range value {
			if !StrInSlice(entry, merged[key]) {
				merged[key] = append(merged[key], entry)
			}
		}
	}
	return merged
}
