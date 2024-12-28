package ospf_cnn

import (
	"fmt"
	"go.uber.org/zap"
)

var logger *zap.Logger

func SetLogger(log *zap.Logger) {
	logger = log
}

func logDebug(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

func logWarn(format string, args ...interface{}) {
	logger.Warn(fmt.Sprintf(format, args...))
}

func logErr(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

func LogImportant(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}
