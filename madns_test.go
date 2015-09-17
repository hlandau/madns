package madns

import (
	"crypto"
	"github.com/hlandau/degoutils/log"
	"github.com/miekg/dns"
	"gopkg.in/hlandau/madns.v1/merr"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"testing"
)

type test struct {
	Queries   []*query
	Responses map[string]*response
}

type query struct {
	QName  string
	QType  string
	DNSSEC bool // Query: DNSSEC OK?
	Result string
	AA     bool
	AN     []string
	NS     []string
	AD     []string
}

func (q *query) checkResponsesMatch(t *testing.T, msg *dns.Msg) {
	if q.AA != msg.Authoritative {
		t.Errorf("Authoritative flag did not match expectations")
	}
	if dns.RcodeToString[msg.Rcode] != q.Result {
		t.Errorf("Result rcode (%s) did not match expectation (%s)", dns.RcodeToString[msg.Rcode], q.Result)
		t.Errorf("Message: " + msg.String())
	}
	q.checkSectionMatches(t, msg.Answer, q.AN, "answer")
	q.checkSectionMatches(t, msg.Ns, q.NS, "authority")
	q.checkSectionMatches(t, msg.Extra, q.AD, "additional")
}

func (q *query) checkSectionMatches(t *testing.T, rrs []dns.RR, ref []string, secname string) {
	if secname == "additional" && len(rrs) > 0 {
		if rrs[0].Header().Rrtype == dns.TypeOPT {
			rrs = rrs[1:]
		}
	}

	// Additional records are returned in random order due to madns internal architecture
	// and go's map randomization which is fine, but we need to sort them here to get them
	// to match up.
	rrss := []string{}
	for _, rr := range rrs {
		rrss = append(rrss, rr.String())
	}
	sort.Strings(rrss)

	refss := []string{}
	for _, s := range ref {
		rsr, err := dns.NewRR(s)
		log.Panice(err)
		refss = append(refss, rsr.String())
	}
	sort.Strings(refss)

	if len(rrs) != len(ref) {
		s := ""
		for _, r := range rrs {
			s += r.String()
			s += "\n"
		}
		t.Errorf("Expected %d RRs in %s section but got %d:\n%s", len(ref), secname, len(rrs), s)
		return
	}
	for i := range refss {
		if refss[i] != rrss[i] {
			log.Info("MISMATCH:")
			log.Info("  ", refss[i])
			log.Info("  ", rrss[i])
			t.Errorf("Response RR mismatch")
		}
	}
}

type response struct {
	RRs []string
	Err string
}

func (b *test) Lookup(qname string) (rrs []dns.RR, err error) {
	qname = dns.Fqdn(qname)
	if r, ok := b.Responses[qname]; ok {
		for _, rrstr := range r.RRs {
			rr, err := dns.NewRR(rrstr)
			log.Panice(err)

			rrs = append(rrs, rr)
		}
		err = parseErr(r.Err)
		if len(rrs) == 0 && err == nil {
			err = merr.ErrNoResults
		}
	} else {
		err = merr.ErrNoSuchDomain
	}
	return
}

func parseErr(e string) error {
	switch e {
	case "":
		return nil
	case "REFUSED":
		return merr.ErrNotInZone
	case "NXDOMAIN":
		return merr.ErrNoSuchDomain
	default:
		panic("unknown error: " + e)
	}
}

func testWith(t *testing.T, tst *test) {
	cfg := &EngineConfig{
		Backend:    tst,
		KSK:        testKSK,
		KSKPrivate: testKSKPrivate,
		ZSK:        testZSK,
		ZSKPrivate: testZSKPrivate,
	}

	e, err := NewEngine(cfg)
	if err != nil {
		t.Errorf("Cannot create engine")
		return
	}

	for _, q := range tst.Queries {
		var res *dns.Msg
		prw := &psuedorw{
			writeMsg: func(m *dns.Msg) error {
				if res != nil {
					panic("cannot send multiple responses")
				}

				res = m
				return nil
			},
		}
		req := &dns.Msg{}
		req.SetQuestion(q.QName, parseType(q.QType))
		req.SetEdns0(4096, q.DNSSEC)

		e.ServeDNS(prw, req)
		if res == nil {
			t.Errorf("Got nil response from ServeDNS")
		} else {
			q.checkResponsesMatch(t, res)
		}
	}
}

func parseType(s string) uint16 {
	return dns.StringToType[s]
}

func TestResponses(t *testing.T) {
	f, err := os.Open("test.yaml")
	log.Panice(err)

	b, err := ioutil.ReadAll(f)
	log.Panice(err)

	var tests []*test
	err = yaml.Unmarshal(b, &tests)
	log.Fatale(err)

	for _, tt := range tests {
		testWith(t, tt)
	}
}

// DNSSEC keys used for testing purposes only
func init() {
	testKSKa, err := dns.NewRR(testKSKs)
	log.Panice(err)

	testZSKa, err := dns.NewRR(testZSKs)
	log.Panice(err)

	testKSK = testKSKa.(*dns.DNSKEY)
	testZSK = testZSKa.(*dns.DNSKEY)

	testKSKPrivate, err = testKSK.NewPrivateKey(testKSKPrivates)
	log.Panice(err)
	testZSKPrivate, err = testZSK.NewPrivateKey(testZSKPrivates)
	log.Panice(err)
}

var testKSK *dns.DNSKEY
var testKSKPrivate crypto.PrivateKey
var testZSK *dns.DNSKEY
var testZSKPrivate crypto.PrivateKey

var testKSKs = `test. IN DNSKEY 257 3 8 AwEAAbl6k1vj0oJ8fvRW0ouMxGfUVz0/HGnaRj7oSolrxO+wvpZf+jX8 WKdE7TfKiVTipXfHhMe655Ltb5IKcrygyDCgLDyBOv8HygnZNznh8GCN KVHNp14lOLlQWzW3WYTrvwG5iswQuJq/f0WKrWNe9glIP/nL4l0CNEZs 6qgc2x47+07wogpTip0BLdjGP59+tXZTRlmw4z7ELE1chZxOtVjbMfIC ANjET59SYuN8nxZPy6mPqpjV65OvRpw+IYPnWLrIm0laPnOFePfiUF1v eag/NDhgE5kGFDMqsdNkDv8QX5tAICrnduillqNtm+AzUM9pERFaJeMn 3RpDLR4nzdc=`
var testKSKPrivates = `Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: uXqTW+PSgnx+9FbSi4zEZ9RXPT8cadpGPuhKiWvE77C+ll/6NfxYp0TtN8qJVOKld8eEx7rnku1vkgpyvKDIMKAsPIE6/wfKCdk3OeHwYI0pUc2nXiU4uVBbNbdZhOu/AbmKzBC4mr9/RYqtY172CUg/+cviXQI0RmzqqBzbHjv7TvCiClOKnQEt2MY/n361dlNGWbDjPsQsTVyFnE61WNsx8gIA2MRPn1Ji43yfFk/LqY+qmNXrk69GnD4hg+dYusibSVo+c4V49+JQXW95qD80OGATmQYUMyqx02QO/xBfm0AgKud26KWWo22b4DNQz2kREVol4yfdGkMtHifN1w==
PublicExponent: AQAB
PrivateExponent: eQW75PdQQggNpkyIcLnW5ZCto67sUT01HJLhH62MAIGoueHCFzuidPIKfp7O4O5J3U/4GYKg20PFytq6Zs3aEbBRbOE9p25jq+1plYERIU66KUAw9sL+shv2h6Qs6wgPx4ZTRDec3Iwa9Ts5S1+I1iGobMtV1i48Ab/LlQnPB3grW4Ix56pil5KPiBW+eGDe3MSivBn/InnlJ5dJVh7WGdUYlHAHtKzV86DQQwk9e55H+jcaEt2yrZYN0iEwx7OoKVA7GcSxMvGW5B8dvpiLs5lWoCwa7/816Cb9xG3zXhhX6ej7Nu7OAlMOgOqGEu4XE9rzJQb0WP0xzq8742s50Q==
Prime1: 336a+aBmbUtOyT5dPQ4KFX1DPuwiedA0wmHVWR6yWKJ4+OO+u34COhkPCKNGQpqD6scqo30h2MwpDb1NBETyr9Q+Sp/dPkmhPLbRb95kTgdYJbqehf9xB7Sc8tM/b1LxRWV50UJI+xcrD/BigUaCyWEf2BBKtEEAISEhu+mThHU=
Prime2: 1HSGw3+DI0UkWQVrYJ4IC0eAmr4MTZpsjMPn6X3u20QCEDGdulpV+VAOPWh+Sx4C6PB7Dos2LWmEmOtN3ZQtvK+/lOK4vclAMN6MzQR71j8WPeiBUm1yrJerDp04xqINwMrWEf1CxmGCqbu3w6FEhLBzNPUTE1UcL/JfGdtMz5s=
Exponent1: kwYtmzQKzbFx5e+R1L1sotBhsX4T/ACdBJbpjBQmjSps3IauDZeKjX+4pR0L9nrBd2yIPz7tSjqccz5p8PoOkN7WD691EynK2S8HPkmVwMMSGNfYuxvc1o3ZheC0ZV6x+84SwjeR3SRTnsurcZHaLfInybKGAmiUVjb+gyjYc5U=
Exponent2: Wny6/T8tEnObdJL7Ve5ZDLzKiJ3TTaYs/5NdDjTF6/u+STlorXtWTNaNChicWdARezcZomsmixb7E8p8opg/FrNgDMC34JV70pSnMZbsS6cZCQsjMYFOKzZ588KA8REKfIenv4e3zhiv9yztqtPgBAfHOdH76usAE2fOm4us3ms=
Coefficient: vM/4XLV1OFjOu4k56vfms740bBbtx4EKSxCwX/5G9Kv/5l16TLDDHptprsCMXkeiVPtX6Z7MQjhSCWHmPz2NJeo5hB0rDMfyK6+CWFKobSZJI1xU4jcKvROZfxp4NZPC9hm3MgbTS5Xi0sTj4+7j9pINQSnOVU+QK9ZL0hlulVk=
Created: 20141023114435
Publish: 20141023114435
Activate: 20141023114435`
var testZSKs = `test. IN DNSKEY 256 3 8 AwEAAcvVQXYfm05Le/TE14OT5xy+CixHxVQcKW7B3blAXVnEPgJ3bO8o hReix0q3ep7e6epc687FeE1YErjJsawxSsX3ZfwrBWECKKkUsxBs3XHQ wPYbNsUnTiWmOPsonc1ANfM8IM5eAkG+zXtIOB/5NiQaieZimd5770Z4 eXNhVWqla4EGgVGZ4xp32Xfz+gkYbGy8FX56X1MMFNuaE4R0TrK48rki 9M44WDyhEHOTqPiSB3mTD6oDoKzitenIPS39SMPD/jrsB+z51ksDE9Ci oMUNUvqhq7nYiz6icYDE+/f1qveWBn7okd23RcjCap46a6i6zOpDLsTe dt8eptLcYnk=`
var testZSKPrivates = `Private-key-format: v1.3
Algorithm: 8 (RSASHA256)
Modulus: y9VBdh+bTkt79MTXg5PnHL4KLEfFVBwpbsHduUBdWcQ+Ands7yiFF6LHSrd6nt7p6lzrzsV4TVgSuMmxrDFKxfdl/CsFYQIoqRSzEGzdcdDA9hs2xSdOJaY4+yidzUA18zwgzl4CQb7Ne0g4H/k2JBqJ5mKZ3nvvRnh5c2FVaqVrgQaBUZnjGnfZd/P6CRhsbLwVfnpfUwwU25oThHROsrjyuSL0zjhYPKEQc5Oo+JIHeZMPqgOgrOK16cg9Lf1Iw8P+OuwH7PnWSwMT0KKgxQ1S+qGrudiLPqJxgMT79/Wq95YGfuiR3bdFyMJqnjprqLrM6kMuxN523x6m0txieQ==
PublicExponent: AQAB
PrivateExponent: ZnZc4bQhrcnkFbadX1cJ5jjhhEDPwOgnK7XobycbxfQP981wxQfpX2hEJhr1WMdVbqonH1nEj5ymTJ2W4qgknj8u1QQLQCiFp/jvymHvLzdwyEYF0jVf4y0bl6VjLboJZKvlEdfP6pyvTjmPfQMZZCyzBUyrbFuAfDwzUPyso15+Qj7EH8JJIno/Va7jjqWRUS0IgEM7U81z1+1DU0DcMGXd4WP3aD0ADEuSg3UB/+B2QTtcGTSfy3efEsJzz+yZfV9O/xFucZAmRGM0mtdsgKzygATkZaq/cO8lXMZaXR8j7cLNuzQwCwt+1EboCKg3AOsjnHmazPj1eXRVz2LYAQ==
Prime1: 7fI6mmu8i5aUaTiV8P8mGGK7PuqVYuK6pluAZblD9vaqugtxFsSJyjWDUMJpcuxuQwl8xHqoxxyDXW8LxDOEi2fQZTHxxy+3bfB3HCu1TUjY/IGxP8spxjPxaFLuV01Em39cCW8qWjxWmsQnqHUdbcW5h/bxMHBUp2kBYacF9dE=
Prime2: 20xtHH8dzRiwEz9hkbL3rMKGa4x3u3uQaJ1vIcqos1uOy1WHZtUt7lAiHBQTKtHPDKlkRU5O2BI98VPO8m64E3GkLYAVoBQttSfes+X70N+YxgWgMWoG4av2HZnqmvEdOKXN2sLkDR1fGW0/ZycfO3wKjx4cuQatWbM1pSB0xCk=
Exponent1: cFaFPnSQ7qIn7Ulu2PnNJYQvfPPJlYcPsgzPILeIE+e/ENjoCmS93P7IwW8X0881+2ZWRnjWiDK4/nq35migMiTQKYab7HtlsXzu7xjfnt4+u3ALm9+yGEZbufI1Xng3ZOaLMFUQfMux452qT4kDXNkVz9BRbJoMDYGwykbNtJE=
Exponent2: Fp7DgnT6NfWd895NyiGTupY2F1Hd59DPDHtwwyOMUzPWftLLrKfAnRxW6F6Ju5j4qm2ukheJum/nQ8VJS2hwRFEshiT4FhL+w/jg192ZI+psb8CUzYQKQazjLhp6QJEuWnF/0ljX/SJSdOT37UPzzMb2r9yDSfKOXvpFRksawEE=
Coefficient: HR+bWfg4tItQoRA+vk3ziYN+1yfYcB3zfhccFiP2bVRxiiuvo7HjLS5mlu2jrXChJJMEHWxFSjguSpsuiwUdkUC+Uo6U49HLGVqPMdd1X8XShnRYvwhALv7cAwmVFCETmElLLqAcTWFyzrQOLt+Jrexix2tsx4tICUVp5QgTuQA=
Created: 20141023114438
Publish: 20141023114438
Activate: 20141023114438`

// Psuedo dns.ResponseWriter for getting the response message.
type psuedorw struct {
	writeMsg func(m *dns.Msg) error
}

func (p *psuedorw) LocalAddr() net.Addr {
	n, err := net.ResolveIPAddr("ip", "127.0.0.1")
	log.Panice(err)
	return n
}

func (p *psuedorw) RemoteAddr() net.Addr {
	n, err := net.ResolveIPAddr("ip", "127.0.0.1")
	log.Panice(err)
	return n
}

func (p *psuedorw) WriteMsg(m *dns.Msg) error {
	return p.writeMsg(m)
}

func (p *psuedorw) Write(b []byte) (int, error) {
	panic("not supported")
}

func (p *psuedorw) Close() error {
	panic("not supported")
}

func (p *psuedorw) TsigStatus() error {
	panic("not supported")
}

func (p *psuedorw) TsigTimersOnly(b bool) {
	panic("not supported")
}

func (p *psuedorw) Hijack() {
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
