package ffuf

import (
	"path/filepath"

	"github.com/adrg/xdg"
)

var (
	// VERSION 保存当前版本号
	VERSION = "2.1.0"
	// VERSION_APPENDIX 保存附加的版本定义
	VERSION_APPENDIX = "-dev"
	// CONFIGDIR 定义使用XDG基础目录规范的配置目录路径
	CONFIGDIR = filepath.Join(xdg.ConfigHome, "ffuf")
	// HISTORYDIR 定义存储历史文件的目录路径
	HISTORYDIR = filepath.Join(CONFIGDIR, "history")
	// SCRAPERDIR 定义抓取器配置和数据的目录路径
	SCRAPERDIR = filepath.Join(CONFIGDIR, "scraper")
	// AUTOCALIBDIR 定义自动校准数据和配置的目录路径
	AUTOCALIBDIR = filepath.Join(CONFIGDIR, "autocalibration")
)
