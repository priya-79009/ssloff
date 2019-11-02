package ssloff

const kChannelSize = 1024 * 1024

// msgType
const (
	kClientInputConnect    = 1
	kClientInputUp         = 2
	kClientInputUpEOF      = 3
	kClientClose           = 4
	kRemoteInputDown       = 5
	kRemoteInputDownEOF    = 6
	kRemoteClose           = 8
	kLocalClose            = 9
	kClientInputConnectSSL = 10
)

const kMsgRecvMaxLen = 512 * 1024
const kReaderBuf = 128 * 1024
