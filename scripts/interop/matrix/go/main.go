// Interop matrix driver, Go reference client (C1).
//
// Copied by run.sh into an aggregator-go checkout as cmd/interop-matrix (it needs internal/
// packages) and run against one server. It prints one JSON line per scenario:
//
//	{"client":"go","scenario":"2","name":"...","status":"PASS|FAIL|N-A","evidence":"..."}
//
// Environment: IX_URL, IX_TRUSTBASE (RootTrustBase JSON), IX_PARTITION, IX_N (default 6),
// IX_CASES (envelope_cases.json), IX_RETAINED (views the server retains; 0 = unknown),
// IX_ROUND_MS (server round duration, used to size waits).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/aggregator-go/internal/proofverify"
	"github.com/unicitynetwork/aggregator-go/internal/signing"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
	"github.com/unicitynetwork/aggregator-go/pkg/consolidation"
	"github.com/unicitynetwork/aggregator-go/pkg/consolidation/client"
	"github.com/unicitynetwork/aggregator-go/pkg/noninclusion"
)

var (
	url       = os.Getenv("IX_URL")
	hc        = &http.Client{Timeout: 30 * time.Second}
	partition types.PartitionID
	tb        types.RootTrustBase
)

func emit(scn, name, status, evidence string) {
	b, _ := json.Marshal(map[string]string{"client": "go", "scenario": scn, "name": name, "status": status, "evidence": evidence})
	fmt.Println(string(b))
}

type rpcErr struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (e *rpcErr) reason() (reason, detail string, indexes map[string][]int) {
	var d struct {
		Reason  string           `json:"reason"`
		Detail  string           `json:"detail"`
		Indexes map[string][]int `json:"indexes"`
	}
	_ = json.Unmarshal(e.Data, &d)
	return d.Reason, d.Detail, d.Indexes
}

func (e *rpcErr) String() string {
	r, d, ix := e.reason()
	return fmt.Sprintf("code=%d msg=%q reason=%s detail=%s indexes=%v", e.Code, e.Message, r, d, ix)
}

// rpcRaw posts body and returns the HTTP status, result and error.
func rpcRaw(body []byte) (int, json.RawMessage, *rpcErr, error) {
	resp, err := hc.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, nil, err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcErr         `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return resp.StatusCode, nil, nil, fmt.Errorf("non-JSON response (%d): %.120s", resp.StatusCode, raw)
	}
	return resp.StatusCode, env.Result, env.Error, nil
}

func rpc(method string, params any) (json.RawMessage, *rpcErr, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	_, res, e, err := rpcRaw(body)
	return res, e, err
}

type item struct {
	req   *api.CertificationRequest
	proof *api.GetInclusionProofResponseV2
}

func newRequest() *api.CertificationRequest { return newRequestExp(nil) }

func newRequestExp(expiresAt *uint64) *api.CertificationRequest {
	key, err := btcec.NewPrivateKey()
	must(err)
	pred := api.NewPayToPublicKeyPredicate(key.PubKey().SerializeCompressed())
	rnd := func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }
	src := signing.CreateDataHash(rnd())
	id, err := api.CreateStateID(pred, src)
	must(err)
	cd := api.CertificationData{OwnerPredicate: pred, SourceStateHash: src, TransactionHash: signing.CreateDataHash(rnd()), ExpiresAt: expiresAt}
	must(signing.NewSigningService().SignCertData(&cd, key.Serialize()))
	return &api.CertificationRequest{StateID: id, CertificationData: cd}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(3)
	}
}

func submit(r *api.CertificationRequest) error {
	res, e, err := rpc("certification_request", r)
	if err != nil {
		return err
	}
	if e != nil {
		return fmt.Errorf("certification_request: %s", e)
	}
	var cr api.CertificationResponse
	if err := json.Unmarshal(res, &cr); err != nil {
		return err
	}
	if cr.Status != "SUCCESS" && cr.Status != "STATE_ID_EXISTS" {
		return fmt.Errorf("status %s", cr.Status)
	}
	return nil
}

// fetchV2 polls one state with the status hint; returns the proof (nil until included) and the hint.
func fetchV2(id api.StateID) (*api.GetInclusionProofResponseV2, string, error) {
	res, e, err := rpc("get_inclusion_proof.v2", map[string]any{"stateId": id.String(), "includeStatus": true})
	if err != nil {
		return nil, "", err
	}
	if e != nil {
		// rugregator's legacy v2 answers: -32021 pending, -32020 unknown (no status object)
		switch e.Code {
		case -32021:
			return nil, "pending(rpc-32021)", nil
		case -32020:
			return nil, "unknown(rpc-32020)", nil
		}
		return nil, "", fmt.Errorf("get_inclusion_proof.v2: %s", e)
	}
	var wrapped api.IncludedProofStatusResponse
	hint := ""
	if len(res) > 0 && res[0] == '{' {
		if err := json.Unmarshal(res, &wrapped); err != nil {
			return nil, "", err
		}
		hint = string(wrapped.Status)
		if wrapped.Proof != nil && wrapped.Proof.InclusionProof != nil && len(wrapped.Proof.InclusionProof.UnicityCertificate) > 0 &&
			wrapped.Proof.InclusionProof.CertificationData != nil {
			return wrapped.Proof, hint, nil
		}
		return nil, hint, nil
	}
	var p api.GetInclusionProofResponseV2
	if err := json.Unmarshal(res, &p); err != nil {
		return nil, "", err
	}
	if p.InclusionProof != nil && len(p.InclusionProof.UnicityCertificate) > 0 && p.InclusionProof.CertificationData != nil {
		return &p, "", nil
	}
	return nil, "", nil
}

// loadTrustBase reads the Go-native trust base JSON (numbers) or the SDK shape (decimal strings).
func loadTrustBase(raw []byte) types.RootTrustBase {
	t := &types.RootTrustBaseV1{}
	if err := json.Unmarshal(raw, t); err == nil {
		return t
	}
	var sdk struct {
		NetworkID  uint16 `json:"networkId"`
		Epoch      string `json:"epoch"`
		EpochStart string `json:"epochStartRound"`
		RootNodes  []struct {
			NodeID string `json:"nodeId"`
			SigKey string `json:"sigKey"`
			Stake  string `json:"stake"`
		} `json:"rootNodes"`
	}
	must(json.Unmarshal(raw, &sdk))
	var nodes []*types.NodeInfo
	for _, n := range sdk.RootNodes {
		key, err := hex.DecodeString(strings.TrimPrefix(n.SigKey, "0x"))
		must(err)
		stake, err := strconv.ParseUint(n.Stake, 10, 64)
		must(err)
		nodes = append(nodes, &types.NodeInfo{NodeID: n.NodeID, SigKey: key, Stake: stake})
	}
	epoch, err := strconv.ParseUint(sdk.Epoch, 10, 64)
	must(err)
	start, err := strconv.ParseUint(sdk.EpochStart, 10, 64)
	must(err)
	out, err := types.NewTrustBase(types.NetworkID(sdk.NetworkID), nodes, types.WithEpoch(epoch), types.WithEpochStart(start))
	must(err)
	return out
}

func resolver(seal *types.UnicitySeal) (types.RootTrustBase, error) {
	if tb.GetNetworkID() == seal.NetworkID && tb.GetEpoch() == seal.Epoch {
		return tb, nil
	}
	return nil, fmt.Errorf("no trust base for network %d epoch %d", seal.NetworkID, seal.Epoch)
}

func main() {
	if url == "" {
		must(fmt.Errorf("IX_URL not set"))
	}
	pid, err := strconv.ParseUint(os.Getenv("IX_PARTITION"), 10, 32)
	must(err)
	partition = types.PartitionID(pid)
	raw, err := os.ReadFile(os.Getenv("IX_TRUSTBASE"))
	must(err)
	tb = loadTrustBase(raw)
	n := 6
	if v, err := strconv.Atoi(os.Getenv("IX_N")); err == nil && v > 0 {
		n = v
	}
	retained, _ := strconv.Atoi(os.Getenv("IX_RETAINED"))
	roundMS, _ := strconv.Atoi(os.Getenv("IX_ROUND_MS"))
	if roundMS == 0 {
		roundMS = 1000
	}

	// ---- scenario 1: submit N, wait with status hints, verify each proof
	var items []item
	for i := 0; i < n; i++ {
		items = append(items, item{req: newRequest()})
	}
	var submitErr error
	hints := map[string]int{}
	deadline := time.Now().Add(time.Duration(roundMS)*time.Millisecond*20 + 30*time.Second)
	missing := 0
	// three waves, each fetched right after its inclusion: the originals carry different seals
	wave := (n + 2) / 3
	for lo := 0; lo < n && submitErr == nil; lo += wave {
		hi := lo + wave
		if hi > n {
			hi = n
		}
		for _, it := range items[lo:hi] {
			if err := submit(it.req); err != nil {
				submitErr = err
				break
			}
		}
		for i := lo; i < hi && submitErr == nil; i++ {
			for time.Now().Before(deadline) {
				p, hint, err := fetchV2(items[i].req.StateID)
				if hint != "" {
					hints[hint]++
				}
				if err != nil {
					submitErr = err
					break
				}
				if p != nil {
					items[i].proof = p
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if items[i].proof == nil {
				missing++
			}
		}
	}
	verifyFail := ""
	if submitErr == nil && missing == 0 {
		sess, err := consolidation.NewSession(consolidation.Policy{PartitionID: partition}, resolver)
		must(err)
		for i, it := range items {
			if err := proofverify.VerifyInclusionProofLocal(it.proof.InclusionProof, it.req); err != nil {
				verifyFail = fmt.Sprintf("item %d local: %v", i, err)
				break
			}
			var uc types.UnicityCertificate
			if err := types.Cbor.Unmarshal(it.proof.InclusionProof.UnicityCertificate, &uc); err != nil {
				verifyFail = fmt.Sprintf("item %d uc decode: %v", i, err)
				break
			}
			if err := sess.VerifySeal(uc.UnicitySeal); err != nil {
				verifyFail = fmt.Sprintf("item %d seal: %v", i, err)
				break
			}
		}
	}
	switch {
	case submitErr != nil:
		emit("1", "submit and wait", "FAIL", submitErr.Error())
		os.Exit(0)
	case missing != 0:
		emit("1", "submit and wait", "FAIL", fmt.Sprintf("%d of %d not included before the deadline; hints=%v", missing, n, hints))
		os.Exit(0)
	case verifyFail != "":
		emit("1", "submit and wait", "FAIL", verifyFail)
	default:
		emit("1", "submit and wait", "PASS", fmt.Sprintf("%d requests included, proofs verified (local + seal); status hints seen while waiting=%v", n, hints))
	}

	// ---- scenario 1b: the request exactly as cmd/commitment builds it (AggregateRequestCount = 1)
	{
		r := newRequest()
		r.AggregateRequestCount = 1
		if err := submit(r); err != nil {
			emit("1b", "reference-tool request (aggregateRequestCount=1)", "FAIL", err.Error())
		} else {
			emit("1b", "reference-tool request (aggregateRequestCount=1)", "PASS", "accepted")
		}
	}

	// ---- scenario 2: consolidate via get_inclusion_proofs.v1 latest (direct unsharded path)
	cfg := client.Config{
		Endpoints: []client.Endpoint{{ShardID: types.ShardID{}, URL: url}},
		Policy:    consolidation.Policy{PartitionID: partition},
		Resolver:  resolver,
		Timeout:   30 * time.Second,
	}
	c, err := client.New(cfg)
	must(err)
	var cItems []client.Item
	for _, it := range items {
		cItems = append(cItems, client.Item{Request: it.req, Proof: it.proof.InclusionProof})
	}
	res, err := c.Consolidate(context.Background(), cItems)
	var masterRoot []byte
	if err != nil {
		emit("2", "consolidate latest (direct unsharded)", "FAIL", err.Error())
	} else {
		ok := res.Stats.Requests == 1 && res.Stats.Waves == 1 && res.Stats.PartitionViewBytes == 0
		ev := fmt.Sprintf("requests=%d waves=%d partitionViewBytes=%d quorumChecks=%d evidenceQuorumChecks=%d leafChecks=%d bodyChecks=%d rootRound=%d",
			res.Stats.Requests, res.Stats.Waves, res.Stats.PartitionViewBytes, res.Counters.QuorumChecks, res.Counters.EvidenceQuorumChecks,
			res.Counters.LeafChecks, res.Counters.BodyChecks, res.RootRound)
		// the direct path authenticates the one common seal once: the evidence check and the master
		// check share it (memoized), so the total of native quorum verifications stays small
		if res.Counters.QuorumChecks > 1 || res.Counters.LeafChecks != n {
			ok = false
			ev += " (expected quorumChecks<=1, leafChecks=N)"
		}
		st := "PASS"
		if !ok {
			st = "FAIL"
		}
		emit("2", "consolidate latest (direct unsharded)", st, ev)
		if len(res.Shards) > 0 && len(res.Shards[0].Proofs) > 0 {
			var uc types.UnicityCertificate
			if err := types.Cbor.Unmarshal(res.Shards[0].Proofs[0].InclusionProof.UnicityCertificate, &uc); err == nil && uc.InputRecord != nil {
				masterRoot = uc.InputRecord.Hash
			}
		}
	}

	ids := func() []string {
		var s []string
		for _, it := range items {
			s = append(s, it.req.StateID.String())
		}
		return s
	}
	batch := func(idList []string, root string) (json.RawMessage, *rpcErr, error) {
		p := map[string]any{"stateIds": idList}
		if root != "" {
			p["stateRoot"] = root
		}
		return rpc("get_inclusion_proofs.v1", p)
	}
	proofCount := func(res json.RawMessage) (int, bool) {
		var r struct {
			Proofs        []json.RawMessage `json:"proofs"`
			PartitionView json.RawMessage   `json:"partitionView"`
		}
		_ = json.Unmarshal(res, &r)
		return len(r.Proofs), len(r.PartitionView) > 0
	}

	// ---- scenario 3: exact-root requests
	if masterRoot == nil {
		emit("3", "exact root", "FAIL", "no latest root known (scenario 2 failed)")
	} else {
		var evid []string
		failed := false
		res3, e, err := batch(ids(), hex.EncodeToString(masterRoot))
		switch {
		case err != nil:
			failed, evid = true, append(evid, err.Error())
		case e != nil:
			failed, evid = true, append(evid, "retained root: "+e.String())
		default:
			cnt, view := proofCount(res3)
			evid = append(evid, fmt.Sprintf("retained root: %d proofs, partitionView=%v", cnt, view))
			if cnt != n || view {
				failed = true
			}
		}
		// a second wave moves the latest root; the first root stays retained, but does not hold the new states
		extra := newRequest()
		must(submit(extra))
		for k := 0; k < 100; k++ {
			p, _, err := fetchV2(extra.StateID)
			must(err)
			if p != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		_, e, err = batch(append(ids(), extra.StateID.String()), hex.EncodeToString(masterRoot))
		if err != nil {
			failed, evid = true, append(evid, err.Error())
		} else if e == nil {
			failed, evid = true, append(evid, "old root unexpectedly contains the new state")
		} else {
			r, d, ix := e.reason()
			evid = append(evid, fmt.Sprintf("old root + new state: code=%d reason=%s detail=%s indexes=%v", e.Code, r, d, ix))
			if e.Code != -32008 || d != "state_not_in_root" || len(ix["not_in_root"]) != 1 || ix["not_in_root"][0] != n {
				failed = true
			}
		}
		unknown := make([]byte, 32)
		_, _ = rand.Read(unknown)
		_, e, err = batch(ids(), hex.EncodeToString(unknown))
		if err != nil {
			failed, evid = true, append(evid, err.Error())
		} else if e == nil {
			failed, evid = true, append(evid, "unknown root unexpectedly served")
		} else {
			r, d, _ := e.reason()
			evid = append(evid, fmt.Sprintf("unknown root: code=%d reason=%s detail=%s", e.Code, r, d))
			if e.Code != -32008 || d != "view_not_retained" {
				failed = true
			}
		}
		st := "PASS"
		if failed {
			st = "FAIL"
		}
		emit("3", "exact root (retained, other-state, unknown)", st, strings.Join(evid, "; "))

		// eviction: only when the server is configured with a small retention
		if retained > 0 && retained <= 40 {
			for i := 0; i < retained+1; i++ {
				r := newRequest()
				must(submit(r))
				for k := 0; k < 100; k++ {
					p, _, err := fetchV2(r.StateID)
					must(err)
					if p != nil {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
			}
			_, e, err := batch(ids(), hex.EncodeToString(masterRoot))
			switch {
			case err != nil:
				emit("3b", "evicted root", "FAIL", err.Error())
			case e == nil:
				emit("3b", "evicted root", "FAIL", "evicted root still served")
			default:
				_, d, _ := e.reason()
				st := "PASS"
				if e.Code != -32008 || d != "view_not_retained" {
					st = "FAIL"
				}
				emit("3b", "evicted root", st, e.String())
			}
		} else {
			emit("3b", "evicted root", "N-A", "server retention not small enough to evict cheaply (IX_RETAINED="+strconv.Itoa(retained)+")")
		}
	}

	// ---- scenario 4: status hints and batch details
	{
		var evid []string
		failed := false
		pend := newRequest()
		var gotPending bool
		for attempt := 0; attempt < 3 && !gotPending; attempt++ {
			if attempt > 0 {
				pend = newRequest()
			}
			must(submit(pend))
			_, hint, err := fetchV2(pend.StateID)
			must(err)
			_, e, err := batch([]string{pend.StateID.String()}, "")
			must(err)
			if e != nil {
				_, d, ix := e.reason()
				evid = append(evid, fmt.Sprintf("v2 hint=%q; batch %s", hint, e))
				if d == "state_pending" && len(ix["pending"]) == 1 && ix["pending"][0] == 0 {
					gotPending = true
				}
			} else {
				evid = append(evid, "batch served the state before the round closed (race)")
			}
			for k := 0; k < 100; k++ {
				p, _, _ := fetchV2(pend.StateID)
				if p != nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		if !gotPending {
			evid = append(evid, "pending not reproduced")
			failed = true
		}
		unk := newRequest() // never submitted
		_, e, err := batch([]string{items[0].req.StateID.String(), unk.StateID.String(), items[1].req.StateID.String()}, "")
		must(err)
		if e == nil {
			failed, evid = true, append(evid, "unknown state served")
		} else {
			_, d, ix := e.reason()
			evid = append(evid, "unknown: "+e.String())
			if e.Code != -32008 || d != "state_unknown" || len(ix["unknown"]) != 1 || ix["unknown"][0] != 1 {
				failed = true
			}
		}
		// v2 hint for an unknown state
		_, hint, err := fetchV2(unk.StateID)
		must(err)
		evid = append(evid, fmt.Sprintf("v2 includeStatus unknown -> %q", hint))
		st := "PASS"
		if failed {
			st = "FAIL"
		}
		emit("4", "status hints (pending/unknown) and data.indexes", st, strings.Join(evid, "; "))
		// expired: a request whose deadline is the next round's reference time passes admission and is dropped
		// when its round pins that time; the hint is only reproducible on a server with a live clock progression
		{
			var uc types.UnicityCertificate
			latestUC := func() bool {
				res, e, err := batch([]string{items[0].req.StateID.String()}, "")
				if err != nil || e != nil {
					return false
				}
				var r struct {
					Proofs []*api.GetInclusionProofResponseV2 `json:"proofs"`
				}
				if json.Unmarshal(res, &r) != nil || len(r.Proofs) != 1 || r.Proofs[0].InclusionProof == nil {
					return false
				}
				return types.Cbor.Unmarshal(r.Proofs[0].InclusionProof.UnicityCertificate, &uc) == nil
			}
			expired := false
			var notes []string
			if latestUC() {
				for off := uint64(0); off < 24 && !expired; off++ {
					// scan the round period: a request that arrives while a round waits for its certificate
					// lands in the next round, which pins a later reference time
					time.Sleep(time.Duration(off) * 60 * time.Millisecond)
					latestUC()
					d := uc.UnicitySeal.Timestamp + 1
					r := newRequestExp(&d)
					if err := submit(r); err != nil {
						notes = append(notes, fmt.Sprintf("attempt %d: rejected at admission: %v", off, err))
						continue
					}
					for k := 0; k < 150; k++ {
						_, e, err := batch([]string{r.StateID.String()}, "")
						must(err)
						if e == nil {
							notes = append(notes, fmt.Sprintf("attempt %d (deadline = latest seal time + 1): included", off))
							break
						}
						_, det, _ := e.reason()
						if det == "state_pending" {
							time.Sleep(100 * time.Millisecond)
							continue
						}
						notes = append(notes, fmt.Sprintf("attempt %d (deadline = latest seal time + 1): %s", off, e))
						expired = det == "state_expired"
						break
					}
					if !expired {
						latestUC() // later rounds moved on
					}
				}
			}
			switch {
			case expired:
				emit("4b", "expired hint", "PASS", strings.Join(notes, "; "))
			default:
				if len(notes) > 4 {
					notes = append(notes[:2], fmt.Sprintf("... %d attempts, none expired", len(notes)))
				}
				emit("4b", "expired hint", "N-A", "not reproduced: "+strings.Join(notes, "; "))
			}
		}
	}

	// ---- scenario 5: non-inclusion
	{
		var evid []string
		failed := false
		ver, err := noninclusion.NewVerifier(noninclusion.Context{Partition: partition, Resolver: resolver})
		must(err)
		absent := newRequest().StateID
		res5, e, err := rpc("get_non_inclusion_proof.v1", map[string]any{"stateId": absent.String()})
		var enc []byte
		switch {
		case err != nil:
			failed, evid = true, append(evid, err.Error())
		case e != nil:
			failed, evid = true, append(evid, "absent id: "+e.String())
		default:
			var r api.GetNonInclusionProofResponseV1
			if err := json.Unmarshal(res5, &r); err != nil {
				failed, evid = true, append(evid, "decode: "+err.Error())
			} else {
				bound, err := r.Proof.ForState(absent)
				must(err)
				out, err := ver.VerifyFor(absent, bound)
				if err != nil {
					failed, evid = true, append(evid, "verify: "+err.Error())
				} else {
					evid = append(evid, fmt.Sprintf("absence verified at round %d (emptyTree=%v)", out.RootRound, out.EmptyTree))
				}
				var s string
				_ = json.Unmarshal(res5, &s)
				enc, _ = hex.DecodeString(strings.TrimPrefix(s, "0x"))
			}
		}
		_, e, err = rpc("get_non_inclusion_proof.v1", map[string]any{"stateId": items[0].req.StateID.String()})
		switch {
		case err != nil:
			failed, evid = true, append(evid, err.Error())
		case e == nil:
			failed, evid = true, append(evid, "present id: served an absence proof")
		default:
			r, d, _ := e.reason()
			evid = append(evid, fmt.Sprintf("present id: code=%d reason=%s detail=%s", e.Code, r, d))
			if e.Code != -32022 {
				failed = true
			}
		}
		// tampering: flip one bit of every byte in turn; an accepted variant is reported
		// only the block number bytes (explicitly unauthenticated metadata) are non-binding; the final
		// byte (recovery id of a quorum-essential signature) must be rejected too (strict single-pass recovery)
		nonBinding := map[int]bool{}
		if len(enc) > 2 {
			head := map[byte]int{0x18: 2, 0x19: 3, 0x1a: 5, 0x1b: 9}[enc[1]]
			if head == 0 {
				head = 1
			}
			for k := 1; k < 1+head; k++ {
				nonBinding[k] = true
			}
		}
		accepted, total := []int{}, 0
		for i := 0; i < len(enc); i++ {
			mut := bytes.Clone(enc)
			mut[i] ^= 0x01
			var r api.GetNonInclusionProofResponseV1
			if r.UnmarshalCBOR(mut) != nil {
				total++
				continue
			}
			total++
			bound, err := r.Proof.ForState(absent)
			if err != nil {
				continue
			}
			v2, _ := noninclusion.NewVerifier(noninclusion.Context{Partition: partition, Resolver: resolver})
			if _, err := v2.VerifyFor(absent, bound); err == nil {
				accepted = append(accepted, i)
			}
		}
		if len(enc) == 0 {
			failed = true
		} else if len(accepted) > 0 {
			// the block number is explicitly unauthenticated metadata: only those bytes may be accepted
			binding := []int{}
			for _, o := range accepted {
				if !nonBinding[o] {
					binding = append(binding, o)
				}
			}
			evid = append(evid, fmt.Sprintf("tamper: %d of %d single-bit flips still verified at offsets %v (non-binding: block number only; binding offsets accepted: %v)", len(accepted), total, accepted, binding))
			failed = failed || len(binding) > 0
		} else {
			evid = append(evid, fmt.Sprintf("tamper: all %d single-bit flips rejected", total))
		}
		st := "PASS"
		if failed {
			st = "FAIL"
		}
		emit("5", "non-inclusion (absent, present, tampered)", st, strings.Join(evid, "; "))
	}

	// ---- scenario 6: error envelope
	{
		var cases struct {
			Cases []struct {
				Name   string  `json:"name"`
				Gen    string  `json:"gen"`
				Method string  `json:"method"`
				Params any     `json:"params"`
				HTTP   int     `json:"http"`
				Code   int     `json:"code"`
				Reason *string `json:"reason"`
				Detail *string `json:"detail"`
			} `json:"cases"`
		}
		b, err := os.ReadFile(os.Getenv("IX_CASES"))
		must(err)
		must(json.Unmarshal(b, &cases))
		id0 := items[0].req.StateID.String()
		var bad []string
		for _, c := range cases.Cases {
			method := "get_inclusion_proofs.v1"
			if c.Method != "" {
				method = c.Method
			}
			var params any = c.Params
			switch c.Gen {
			case "ids257":
				var l []string
				for i := 0; i < 257; i++ {
					l = append(l, fmt.Sprintf("%064x", i+1))
				}
				params = map[string]any{"stateIds": l, "stateRoot": "latest"}
			case "oversize":
				params = map[string]any{"stateIds": []string{id0}, "stateRoot": "latest", "pad": strings.Repeat("a", 70*1024)}
			default:
				pb, _ := json.Marshal(c.Params)
				params = json.RawMessage(strings.ReplaceAll(string(pb), "{ID}", id0))
			}
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
			status, _, e, err := rpcRaw(body)
			if err != nil {
				bad = append(bad, c.Name+": "+err.Error())
				continue
			}
			if e == nil {
				bad = append(bad, c.Name+": no error")
				continue
			}
			r, d, _ := e.reason()
			diffs := ""
			if status != c.HTTP {
				diffs += fmt.Sprintf(" http=%d(want %d)", status, c.HTTP)
			}
			if e.Code != c.Code {
				diffs += fmt.Sprintf(" code=%d(want %d)", e.Code, c.Code)
			}
			if c.Reason != nil && r != *c.Reason {
				diffs += fmt.Sprintf(" reason=%q(want %q)", r, *c.Reason)
			}
			if c.Detail != nil && d != *c.Detail {
				diffs += fmt.Sprintf(" detail=%q(want %q)", d, *c.Detail)
			}
			if diffs != "" {
				bad = append(bad, c.Name+":"+diffs)
			}
		}
		if len(bad) == 0 {
			emit("6", "error envelope (limits, malformed params)", "PASS", fmt.Sprintf("%d cases match the reference envelope", len(cases.Cases)))
		} else {
			emit("6", "error envelope (limits, malformed params)", "FAIL", strings.Join(bad, "; "))
		}
	}
}
