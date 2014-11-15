package madns

import "github.com/miekg/dns"
import "github.com/hlandau/madns/merr"
import "strings"

//import "github.com/hlandau/degoutils/log"
import "sort"
import "runtime"
import "expvar"

const version string = "1.0"

var cNumQueries = expvar.NewInt("madns.numQueries")
var cNumQueriesNoEDNS = expvar.NewInt("madns.numQueriesNoEDNS")
var cBackendLookups = expvar.NewInt("madns.numBackendLookups")

// Interface for querying an abstract zone file.
type Backend interface {
	// Lookup all resource records having a given fully-qualified owner name,
	// regardless of type or class. Returns a slice of all those resource records
	// or an error.
	//
	// The returned slice may contain both authoritative and non-authoritative records
	// (for example, NS records for delegations and glue records.)
	//
	// The existence of wildcard records will be determined by doing a lookup for a name
	// like "*.example.com", so there is no need to process the wildcard logic other than
	// to make sure such a lookup functions correctly.
	Lookup(qname string) (rrs []dns.RR, err error)
}

// DNS query engine implementing dns.Handler. Suitable for exposure directly to
// the network via ServeMux.
type Engine interface {
	dns.Handler
}

// Engine Configuration.
type EngineConfig struct {
	Backend    Backend

	// Key signing key. If not set, ZSK is used for everything.
	KSK        *dns.DNSKEY
	KSKPrivate dns.PrivateKey

	// Zone signing key. DNSSEC is disabled if this isn't set.
	ZSK        *dns.DNSKEY
	ZSKPrivate dns.PrivateKey

	// Version string to report in 'version.bind.'
	VersionString string
}

// Creates a new query engine.
func NewEngine(cfg *EngineConfig) (e Engine, err error) {
	ee := &engine{}
	ee.cfg = *cfg

	e = ee
	return
}

type engine struct {
	cfg EngineConfig
}

func (e *engine) ServeDNS(rw dns.ResponseWriter, reqMsg *dns.Msg) {
	cNumQueries.Add(1)

	tx := stx{}
	tx.req = reqMsg
	tx.res = &dns.Msg{}
	tx.res.SetReply(tx.req)
	tx.res.Authoritative = true
	tx.res.Compress = true
	tx.e = e
	tx.typesAtQname = map[uint16]struct{}{}
	tx.additionalQueue = map[string]struct{}{}

	opt := tx.req.IsEdns0()
	if opt != nil {
		tx.res.Extra = append(tx.res.Extra, opt)
	} else {
		cNumQueriesNoEDNS.Add(1)
	}

	for _, q := range tx.req.Question {
		tx.qname = strings.ToLower(q.Name)
		tx.qtype = q.Qtype
		tx.qclass = q.Qclass

		err := tx.addAnswers()
		if err != nil {
			if err == merr.ErrNoResults {
				tx.rcode = 0
			} else if err == merr.ErrNoSuchDomain {
				tx.rcode = dns.RcodeNameError
			} else if err == merr.ErrNotInZone {
				tx.rcode = dns.RcodeRefused
			} else if tx.rcode == 0 {
				//log.Info("Issuing SERVFAIL because of error: ", err)
				tx.rcode = dns.RcodeServerFailure
			}
		}
	}

	tx.res.SetRcode(tx.req, tx.rcode)

	rw.WriteMsg(tx.res) /* ignore err */
}

type stx struct {
	req    *dns.Msg
	res    *dns.Msg
	qname  string
	qtype  uint16
	qclass uint16
	e      *engine
	rcode  int

	typesAtQname    map[uint16]struct{}
	additionalQueue map[string]struct{}
	soa             *dns.SOA
	delegationPoint string // domain name at which the selected delegation was found

	// The query was made for the selected delegation's name.
	// i.e., if a lookup a.b.c.d has been made, and b.c.d  has been chosen as the
	// closest available delegation to serve, this is false. Whereas if b.c.d is
	// queried, this is true.
	queryIsAtDelegationPoint bool

	// Add a 'consolation SOA' to the Authority section?
	// Usually set when there are no results. This has to be done later, because
	// we add DNSKEYs (if requested) at a later time and need to be able to quash
	// this at that time in case adding DNSKEYs means an answer has stopped being
	// empty of results.
	consolationSOA bool

	// Don't NSEC for having no answers. Used for qtype==DS.
	suppressNSEC bool
}

func (tx *stx) blookup(qname string) (rrs []dns.RR, err error) {
	cBackendLookups.Add(1)

	rrs, err = tx.e.cfg.Backend.Lookup(qname)
	if err == nil && len(rrs) == 0 {
		err = merr.ErrNoResults
	}
	return
}

func (tx *stx) addAnswers() error {
	if tx.qclass != dns.ClassINET && tx.qclass != dns.ClassANY {
		return tx.addAnswersStrange()
	}

	err := tx.addAnswersMain()
	if err != nil {
		//log.Info("Error response (addAnswersMain): ", err)
		return err
	}

	// If we are at the zone apex...
	if _, ok := tx.typesAtQname[dns.TypeSOA]; tx.soa != nil && ok {
		// Add DNSKEYs.
		if tx.istype(dns.TypeDNSKEY) {
			tx.e.cfg.KSK.Hdr.Name = tx.soa.Hdr.Name
			tx.e.cfg.ZSK.Hdr.Name = tx.e.cfg.KSK.Hdr.Name

			tx.res.Answer = append(tx.res.Answer, tx.e.cfg.KSK)
			tx.res.Answer = append(tx.res.Answer, tx.e.cfg.ZSK)

			// cancel sending a consolation SOA since we're giving DNSKEY answers
			tx.consolationSOA = false
		}

		tx.typesAtQname[dns.TypeDNSKEY] = struct{}{}
	}

	//
	if tx.consolationSOA && tx.soa != nil {
		tx.res.Ns = append(tx.res.Ns, tx.soa)
	}

	err = tx.addNSEC()
	if err != nil {
		return err
	}

	err = tx.addAdditional()
	if err != nil {
		return err
	}

	err = tx.signResponse()
	if err != nil {
		return err
	}

	return nil
}

func (tx *stx) addAnswersStrange() error {
	if tx.qclass != dns.ClassCHAOS {
		return merr.ErrNotInZone // Hmm...
	}

	// CHAOS responses are not signed, NSEC'd or otherwise DNSSEC'd in any way.
	switch tx.qname {
	case "version.bind.", "version.server.":
		vs := tx.e.cfg.VersionString
		if len(vs) > 0 {
			vs += " "
		}
		tx.res.Answer = append(tx.res.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "version.bind.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
				Ttl:    0,
			},
			Txt: []string{vs + "madns/" + version + " " + runtime.Version() + "/" + runtime.GOARCH + "/" + runtime.GOOS + "/" + runtime.Compiler},
		})
	// TODO: hostname.bind.
	// TODO: id.server.
	default:
		return merr.ErrNoSuchDomain
	}

	return nil
}

func (tx *stx) addAnswersMain() error {
	var soa *dns.SOA
	var origq []dns.RR
	var origerr error
	var firsterr error
	var nss []dns.RR
	firstNSAtLen := -1
	firstSOAAtLen := -1

	// We have to find out the zone root by trying to find SOA for progressively shorter domain names.
	norig := strings.TrimRight(tx.qname, ".")
	n := norig

A:
	for len(n) > 0 {
		rrs, err := tx.blookup(n)
		if len(n) == len(norig) { // keep track of the results for the original qname
			origq = rrs
			origerr = err
		}
		if err == nil { // success
			for i := range rrs {
				t := rrs[i].Header().Rrtype
				switch t {
				case dns.TypeSOA:
					// found the apex of the closest zone for which we are authoritative
					// We haven't found any nameservers at this point, so we can serve without worrying about delegations.
					if soa == nil {
						soa = rrs[i].(*dns.SOA)
					}

					// We have found a SOA record at this level. This is preferred over everything
					// so we can break now.
					if firstSOAAtLen < 0 {
						firstSOAAtLen = len(n)
					}
					break A

				case dns.TypeNS:
					// found an NS on the path; we are not authoritative for this owner or anything under it
					// We need to return Authority data regardless of the nature of the query.
					nss = rrs

					// There could also be a SOA record at this level that we haven't reached yet.
					if firstNSAtLen < 0 {
						firstNSAtLen = len(n)

						tx.delegationPoint = dns.Fqdn(n)
						//log.Info("DELEGATION POINT: ", tx.delegationPoint)

						if n == norig {
							tx.queryIsAtDelegationPoint = true
						}
					}

				default:
				}
			}
		} else if firsterr == nil {
			firsterr = err
		}

		nidx := strings.Index(n, ".")
		if nidx < 0 {
			break
		}
		n = n[nidx+1:]
	}

	if soa == nil {
		// If we didn't even get a SOA at any point, we don't have any appropriate zone for this query.
		return merr.ErrNotInZone
	}

	tx.soa = soa

	if firstSOAAtLen >= firstNSAtLen {
		// We got a SOA and zero or more NSes at the same level; we're not a delegation.
		return tx.addAnswersAuthoritative(origq, origerr)
	}
	
	// We have a delegation.
	return tx.addAnswersDelegation(nss)
}

func (tx *stx) addAnswersAuthoritative(rrs []dns.RR, origerr error) error {
	// A call to blookup either succeeds or fails.
	//
	// If it fails:
	//   ErrNotInZone     -- you're looking fundamentally in the wrong place; if there is no other
	//                       appropriate zone, fail with REFUSED
	//   ErrNoSuchDomain  -- there are no records at this name of ANY type, nor are there at any
	//                       direct or indirect descendant domain; fail with NXDOMAIN
	//   ErrNoResults     -- There are no records of the given type of class. However, there are
	//                       other records at the given domain and/or records at a direct or
	//                       indirect descendant domain; NOERROR
	//   any other error  -- SERVFAIL
	//
	// If it succeeds:
	//   If there are zero records, treat the response as ErrNoResults above. Otherwise, each record
	//   can be classified into one of the following categories:
	//
	//     - A NS record not at the zone apex and thus not authoritative (handled in addAnswersDelegation)
	//
	//     - A record not within the zone and thus not authoritative (glue records)
	//
	//     - A CNAME record (must not be glue) (TODO: DNAME)
	//
	//     - Any other record
	if origerr != nil {
		return origerr
	}

	cn := rrsetHasType(rrs, dns.TypeCNAME)
	if cn != nil && !tx.istype(dns.TypeCNAME) {
		// We have an alias.
		// TODO: check that the CNAME record is actually in the zone and not some bizarro CNAME glue record
		return tx.addAnswersCNAME(cn.(*dns.CNAME))
	}

	// Add every record which was requested.
	for i := range rrs {
		t := rrs[i].Header().Rrtype
		if tx.istype(t) {
			tx.res.Answer = append(tx.res.Answer, rrs[i])
		}

		// Keep track of the types that really do exist here in case we have to NSEC.
		tx.typesAtQname[t] = struct{}{}
	}

	if len(tx.res.Answer) == 0 {
		// no matching records, hand out the SOA (done later, might be quashed)
		tx.consolationSOA = true
	}

	return nil
}

func rrsetHasType(rrs []dns.RR, t uint16) dns.RR {
	for i := range rrs {
		if rrs[i].Header().Rrtype == t {
			return rrs[i]
		}
	}
	return nil
}

func (tx *stx) addAnswersCNAME(cn *dns.CNAME) error {
	tx.res.Answer = append(tx.res.Answer, cn)
	return nil
}

func (tx *stx) addAnswersDelegation(nss []dns.RR) error {
	if tx.qtype == dns.TypeDS /* don't use istype, must not match ANY */ &&
		tx.queryIsAtDelegationPoint {
		// If type DS was requested specifically (not ANY), we have to act like
		// we're handling things authoritatively and hand out a consolation SOA
		// record and NOT hand out NS records. These still go in the Authority
		// section though.
		//
		// If a DS record exists, it's given; if one doesn't, an NSEC record is
		// given.
		added := false
		for _, ns := range nss {
			t := ns.Header().Rrtype
			if t == dns.TypeDS {
				added = true
				tx.res.Answer = append(tx.res.Answer, ns)
			}
		}
		if added {
			tx.suppressNSEC = true
		} else {
			tx.consolationSOA = true
		}
	} else {
		tx.res.Authoritative = false

		// Note that this is not authoritative data and thus does not get signed.
		for _, ns := range nss {
			t := ns.Header().Rrtype
			if t == dns.TypeNS || t == dns.TypeDS {
				tx.res.Ns = append(tx.res.Ns, ns)
			}
			if t == dns.TypeNS {
				ns_ := ns.(*dns.NS)
				tx.queueAdditional(ns_.Ns)
			}
			if t == dns.TypeDS {
				tx.suppressNSEC = true
			}
		}
	}

	// Nonauthoritative NS records are still included in the NSEC extant types list
	tx.typesAtQname[dns.TypeNS] = struct{}{}

	return nil
}

func (tx *stx) queueAdditional(name string) {
	tx.additionalQueue[name] = struct{}{}
}

func (tx *stx) addNSEC() error {
	if !tx.useDNSSEC() || tx.suppressNSEC {
		return nil
	}

	// NSEC replies should be given in the following circumstances:
	//
	//   - No ANSWER SECTION responses for type requested, qtype != DS
	//   - No ANSWER SECTION responses for type requested, qtype == DS
	//   - Wildcard, no data responses
	//   - Wildcard, data response
	//   - Name error response
	//   - Direct NSEC request

	if len(tx.res.Answer) == 0 {
		err := tx.addNSEC3RR()
		if err != nil {
			return err
		}
	}

	return nil
}

func (tx *stx) addNSEC3RR() error {
	// deny the name
	err := tx.addNSEC3RRActual(tx.qname, tx.typesAtQname)
	if err != nil {
		return err
	}

	// DEVEVER.BIT.
	// deny DEVEVER.BIT. (DS)
	// deny *.BIT.

	// deny the existence of a wildcard that could have served the name

	return nil
}

func (tx *stx) addNSEC3RRActual(name string, tset map[uint16]struct{}) error {
	tbm := []uint16{}
	for t := range tset {
		tbm = append(tbm, t)
	}

	sort.Sort(uint16Slice(tbm))

	nsr1n := dns.HashName(tx.qname, dns.SHA1, 1, "8F")
	nsr1nn := stepName(nsr1n)
	nsr1 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(nsr1n + "." + tx.soa.Hdr.Name),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    600,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 1,
		SaltLength: 1,
		Salt:       "8F",
		HashLength: uint8(len(nsr1nn)),
		NextDomain: nsr1nn,
		TypeBitMap: tbm,
	}
	tx.res.Ns = append(tx.res.Ns, nsr1)

	return nil
}

func (tx *stx) addAdditional() error {
	for aname := range tx.additionalQueue {
		err := tx.addAdditionalItem(aname)
		if err != nil {
			// eat the error
			//return err
		}
	}
	return nil
}

func (tx *stx) addAdditionalItem(aname string) error {
	rrs, err := tx.blookup(aname)
	if err != nil {
		return err
	}
	for _, rr := range rrs {
		t := rr.Header().Rrtype
		if t == dns.TypeA || t == dns.TypeAAAA {
			tx.res.Extra = append(tx.res.Extra, rr)
		}
	}
	return nil
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
