// Verifies the certificates of `stub-anchor fixture` with the native Go
// implementation (bft-go-base UnicityCertificate.Verify, the strict
// trust-base seal verifier) and the aggregator-go consolidation session.
//
//	cargo run -q -p uni-aggregator --bin stub-anchor -- fixture > fixture.json
//	STUB_FIXTURE=$PWD/fixture.json go test ./...
package nativeuc

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
	bhex "github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/aggregator-go/pkg/consolidation"
)

type fixture struct {
	PartitionID   uint32 `json:"partitionId"`
	ShardID       string `json:"shardId"`
	ShardConfHash string `json:"shardConfHash"`
	TrustBase     struct {
		NetworkID  uint16 `json:"networkId"`
		Epoch      string `json:"epoch"`
		EpochStart string `json:"epochStartRound"`
		RootNodes  []struct {
			NodeID string `json:"nodeId"`
			SigKey string `json:"sigKey"`
			Stake  string `json:"stake"`
		} `json:"rootNodes"`
	} `json:"trustBase"`
	Certificates []struct {
		BlockNumber        uint64  `json:"blockNumber"`
		StateRoot          *string `json:"stateRoot"`
		PreviousStateRoot  *string `json:"previousStateRoot"`
		ReferenceTime      uint64  `json:"referenceTime"`
		UnicityCertificate string  `json:"unicityCertificate"`
	} `json:"certificates"`
}

func load(t *testing.T) (*fixture, types.RootTrustBase) {
	path := os.Getenv("STUB_FIXTURE")
	if path == "" {
		t.Skip("STUB_FIXTURE not set")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var f fixture
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Len(t, f.TrustBase.RootNodes, 1)
	n := f.TrustBase.RootNodes[0]
	key, err := hex.DecodeString(n.SigKey)
	require.NoError(t, err)
	epoch, err := strconv.ParseUint(f.TrustBase.Epoch, 10, 64)
	require.NoError(t, err)
	start, err := strconv.ParseUint(f.TrustBase.EpochStart, 10, 64)
	require.NoError(t, err)
	tb, err := types.NewTrustBase(types.NetworkID(f.TrustBase.NetworkID),
		[]*types.NodeInfo{{NodeID: n.NodeID, SigKey: key, Stake: 1}},
		types.WithEpoch(epoch), types.WithEpochStart(start))
	require.NoError(t, err)
	return &f, tb
}

// technicalRecord mirrors bft-core's certification.TechnicalRecord.
type technicalRecord struct {
	_        struct{} `cbor:",toarray"`
	Round    uint64
	Epoch    uint64
	Leader   string
	StatHash bhex.Bytes
	FeeHash  bhex.Bytes
}

func TestStubCertificatesAreNativeValid(t *testing.T) {
	f, tb := load(t)
	conf, err := hex.DecodeString(f.ShardConfHash)
	require.NoError(t, err)
	require.NotEmpty(t, f.Certificates)
	require.NotZero(t, f.PartitionID)

	sess, err := consolidation.NewSession(
		consolidation.Policy{PartitionID: types.PartitionID(f.PartitionID)},
		func(*types.UnicitySeal) (types.RootTrustBase, error) { return tb, nil })
	require.NoError(t, err)

	for _, c := range f.Certificates {
		raw, err := hex.DecodeString(c.UnicityCertificate)
		require.NoError(t, err)
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(raw, &uc), "block %d", c.BlockNumber)

		// the complete native verification: structure, shard path, partition path to the
		// seal hash, strict seal (network, epoch, epoch start, quorum signature)
		require.NoError(t, uc.Verify(tb, crypto.SHA256, types.PartitionID(f.PartitionID), types.ShardID{}, conf),
			"block %d", c.BlockNumber)
		require.NoError(t, types.TrustBaseSealVerifier(tb).VerifySeal(uc.UnicitySeal))
		require.NoError(t, sess.VerifySeal(uc.UnicitySeal))

		// re-encoding is byte-identical, so hashes over the re-encoded record are the signed ones
		again, err := uc.MarshalCBOR()
		require.NoError(t, err)
		require.True(t, bytes.Equal(raw, again), "block %d is not in canonical native encoding", c.BlockNumber)

		// coherent policy
		require.Equal(t, c.BlockNumber, uc.InputRecord.RoundNumber)
		require.Equal(t, c.ReferenceTime, uc.InputRecord.Timestamp)
		require.Equal(t, tb.GetEpoch(), uc.InputRecord.Epoch)
		require.Equal(t, tb.GetEpoch(), uc.UnicitySeal.Epoch)
		require.GreaterOrEqual(t, uc.UnicitySeal.RootChainRoundNumber, tb.GetEpochStart())
		require.True(t, uc.ShardTreeCertificate.Shard.Length() == 0)
		require.Empty(t, uc.ShardTreeCertificate.SiblingHashes)
		require.Empty(t, uc.UnicityTreeCertificate.HashSteps)

		// the state hash is the aggregator root; an empty tree is an empty hash
		if c.StateRoot != nil {
			want, _ := hex.DecodeString(*c.StateRoot)
			require.Equal(t, want, []byte(uc.InputRecord.Hash))
		} else {
			require.Empty(t, uc.InputRecord.Hash)
		}

		// trHash commits to a valid technical record for the next round
		tr := technicalRecord{Round: c.BlockNumber + 1, Epoch: tb.GetEpoch(), Leader: "NODE"}
		h := abhash.New(crypto.SHA256.New())
		h.Write(trFields(&tr))
		sum, err := h.Sum()
		require.NoError(t, err)
		require.Equal(t, sum, []byte(uc.TRHash), "trHash of block %d", c.BlockNumber)
	}
}

// trFields completes the technical record with the profile's fixed hashes.
func trFields(tr *technicalRecord) *technicalRecord {
	stat := sha256sum("rugregator-stub-stat/v1")
	fee := sha256sum("rugregator-stub-fee/v1")
	tr.StatHash, tr.FeeHash = stat, fee
	return tr
}

// The profile is not accepted by luck: each field the stub must get right is rejected when wrong.
func TestNativeVerificationRejectsLegacyShapes(t *testing.T) {
	f, tb := load(t)
	conf, _ := hex.DecodeString(f.ShardConfHash)
	raw, err := hex.DecodeString(f.Certificates[0].UnicityCertificate)
	require.NoError(t, err)
	decode := func() *types.UnicityCertificate {
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(raw, &uc))
		return &uc
	}
	p := types.PartitionID(f.PartitionID)
	verify := func(uc *types.UnicityCertificate) error {
		return uc.Verify(tb, crypto.SHA256, p, types.ShardID{}, conf)
	}
	require.NoError(t, verify(decode()))

	uc := decode()
	uc.TRHash = nil
	require.ErrorContains(t, verify(uc), "TRHash")

	uc = decode()
	uc.UnicityTreeCertificate.Partition = 0
	require.Error(t, verify(uc))
	require.Error(t, decode().Verify(tb, crypto.SHA256, 0, types.ShardID{}, conf), "partition 0")

	uc = decode()
	uc.ShardConfHash = make([]byte, 32)
	require.Error(t, verify(uc), "zero configuration hash")

	uc = decode()
	uc.InputRecord.BlockHash = nil
	require.Error(t, verify(uc), "state changed without a block hash")

	uc = decode()
	uc.UnicitySeal.Epoch = 0
	require.Error(t, verify(uc), "epoch 0 seal")

	uc = decode()
	uc.UnicitySeal.Signatures["NODE"][3] ^= 1
	require.Error(t, verify(uc), "altered signature")

	other, err := types.NewTrustBase(tb.GetNetworkID(), tb.GetRootNodes()[:1], types.WithEpoch(2))
	require.NoError(t, err)
	require.Error(t, types.TrustBaseSealVerifier(other).VerifySeal(decode().UnicitySeal), "other epoch anchor")
}
