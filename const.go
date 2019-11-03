package ssloff

const kChannelSize = 1024 * 1024

// cmd
const (
	kCmdConnect    = 1
	kCmdConnectSSL = 2
	kCmdData       = 3
	kCmdEOF        = 4
	kCmdClose      = 5
)

const kMsgRecvMaxLen = 512 * 1024
const kReaderBuf = 128 * 1024
