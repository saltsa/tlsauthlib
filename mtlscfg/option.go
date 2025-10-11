package mtlscfg

// type Option interface {
// 	apply(*options)
// }

type Option func(o *MTLSConfigurator)

type options struct {
	RemotePeerIdentity string
	LocalPeerIdentity  string
}

func WithLocalPeer(p string) Option {
	return func(mc *MTLSConfigurator) {
		mc.localIdentity = p
	}
}

func WithRemotePeer(p string) Option {
	return func(mc *MTLSConfigurator) {
		mc.remoteIdentity = p
	}
}
