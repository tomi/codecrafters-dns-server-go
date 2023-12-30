package dns

type DnsResolver interface {
	Resolve(msg *Message) *Message
}
