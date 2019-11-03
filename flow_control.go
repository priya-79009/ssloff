package ssloff

type FlowCtrl struct {
	ack uint32 // ack from peer
	snt uint32 // sent to peer
	rcv uint32 // sent to leaf
	win uint32 // flow control window
}

const (
	kFlowIdle    = 0
	kFlowPending = 1
	kFlowPause   = 2
)

func (fc *FlowCtrl) state() uint32 {
	diff := fc.snt - fc.ack
	if diff == 0 {
		return kFlowIdle
	} else if diff <= fc.win {
		return kFlowPending
	} else {
		return kFlowPause
	}
}
