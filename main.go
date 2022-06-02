package main

import (
    "bytes"
	"fmt"
	"time"
	"sort"

	"github.com/coinbase/kryptology/pkg/ted25519/ted25519"
	//"github.com/teamortix/golang-wasm/wasm"
	
	proto "github.com/gogo/protobuf/proto"
	pb "github.com/ipfs/go-ipns/pb"
	//ipns "github.com/ipfs/go-ipns"
	u "github.com/ipfs/go-ipfs-util"
	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/node/basic"
	_ "github.com/ipld/go-ipld-prime/codec/dagcbor"
	ipldcodec "github.com/ipld/go-ipld-prime/multicodec"
	"github.com/multiformats/go-multicodec"
	//mh "github.com/multiformats/go-multihash"
	peer "github.com/libp2p/go-libp2p-core/peer"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	cryptopb "github.com/libp2p/go-libp2p-core/crypto/pb"
)

const (
	validity     = "Validity"
	validityType = "ValidityType"
	value        = "Value"
	sequence     = "Sequence"
	ttl          = "TTL"
)

func createCborDataForIpnsEntry(e *pb.IpnsEntry) ([]byte, error) {
	m := make(map[string]ipld.Node)
	var keys []string
	m[value] = basicnode.NewBytes(e.GetValue())
	keys = append(keys, value)

	m[validity] = basicnode.NewBytes(e.GetValidity())
	keys = append(keys, validity)

	m[validityType] = basicnode.NewInt(int64(e.GetValidityType()))
	keys = append(keys, validityType)

	m[sequence] = basicnode.NewInt(int64(e.GetSequence()))
	keys = append(keys, sequence)

	m[ttl] = basicnode.NewInt(int64(e.GetTtl()))
	keys = append(keys, ttl)

	sort.Sort(cborMapKeyString_RFC7049(keys))

	newNd := basicnode.Prototype__Map{}.NewBuilder()
	ma, err := newNd.BeginMap(int64(len(keys)))
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if err := ma.AssembleKey().AssignString(k); err != nil {
			return nil, err
		}
		if err := ma.AssembleValue().AssignNode(m[k]); err != nil {
			return nil, err
		}
	}

	if err := ma.Finish(); err != nil {
		return nil, err
	}

	nd := newNd.Build()

	enc, err := ipldcodec.LookupEncoder(uint64(multicodec.DagCbor))
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := enc(nd, buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type cborMapKeyString_RFC7049 []string

func (x cborMapKeyString_RFC7049) Len() int      { return len(x) }
func (x cborMapKeyString_RFC7049) Swap(i, j int) { x[i], x[j] = x[j], x[i] }
func (x cborMapKeyString_RFC7049) Less(i, j int) bool {
	li, lj := len(x[i]), len(x[j])
	if li == lj {
		return x[i] < x[j]
	}
	return li < lj
}

func ipnsEntryDataForSigV1(e *pb.IpnsEntry) []byte {
	return bytes.Join([][]byte{
		e.Value,
		e.Validity,
		[]byte(fmt.Sprint(e.GetValidityType())),
	},
		[]byte{})
}

func ipnsEntryDataForSigV2(e *pb.IpnsEntry) ([]byte, error) {
	dataForSig := []byte("ipns-signature:")
	dataForSig = append(dataForSig, e.Data...)

	return dataForSig, nil
}

func main() {

	
	
	entry := new(pb.IpnsEntry)
	
	entry.Value = []byte("/ipfs/bafybeih6ynnlxe4madt43ynit6f34dfbgjnigiggwusaiuwq3c6dmuosqi")
	typ := pb.IpnsEntry_EOL
	entry.ValidityType = &typ
	seq := uint64(0)
	entry.Sequence = &seq
	entry.Validity = []byte(u.FormatRFC3339(time.Date(2030,time.January,1,0,0,0,0,time.UTC)))
	
	ttl, _ := time.ParseDuration("5s")
	ttlNs := uint64(ttl.Nanoseconds())
	entry.Ttl = proto.Uint64(ttlNs)
	
	cborData, _ := createCborDataForIpnsEntry(entry)
	entry.Data = cborData
	
	messageV1 := []byte(ipnsEntryDataForSigV1(entry))
	//messageV2 := []byte(ipnsEntryDataForSigV2(entry))
	
	////////

	config := ted25519.ShareConfiguration{T: 2, N: 3}
	pub, secretShares, _, _ := ted25519.GenerateSharedKey(&config)

	// Each party generates a nonce and we combine them together into an aggregate one
	noncePub1, nonceShares1, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[0], pub, messageV1)
	noncePub2, nonceShares2, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[1], pub, messageV1)
	noncePub3, nonceShares3, _, _ := ted25519.GenerateSharedNonce(&config, secretShares[2], pub, messageV1)

	nonceShares := []*ted25519.NonceShare{
		nonceShares1[0].Add(nonceShares2[0]).Add(nonceShares3[0]),
		nonceShares1[1].Add(nonceShares2[1]).Add(nonceShares3[1]),
		nonceShares1[2].Add(nonceShares2[2]).Add(nonceShares3[2]),
	}

	noncePub := ted25519.GeAdd(ted25519.GeAdd(noncePub1, noncePub2), noncePub3)

	sig1V1 := ted25519.TSign(messageV1, secretShares[0], pub, nonceShares[0], noncePub)
	sig2V1 := ted25519.TSign(messageV1, secretShares[1], pub, nonceShares[1], noncePub)
	sig3V1 := ted25519.TSign(messageV1, secretShares[2], pub, nonceShares[2], noncePub)
	
	/*sig1V2 := ted25519.TSign(messageV2, secretShares[0], pub, nonceShares[0], noncePub)
	sig2V2 := ted25519.TSign(messageV2, secretShares[1], pub, nonceShares[1], noncePub)
	sig3V2 := ted25519.TSign(messageV2, secretShares[2], pub, nonceShares[2], noncePub)*/
	
	pubKey := new(cryptopb.PublicKey)
	pubKey.Type = cryptopb.KeyType_Ed25519
	pubKey.Data = pub.Bytes()
	
	cryptoPubKey, _ := ic.PublicKeyFromProto(pubKey)
	
	ipnsid, _ := peer.IDFromPublicKey(cryptoPubKey)
	ipnsaddr := fmt.Sprintf("/ipns/%s", ipnsid)
	
	fmt.Printf("Public key: %x\n", pub.Bytes())
	fmt.Printf("IPNS Address: %s\n", ipnsaddr)

	fmt.Printf("\nThreshold Sig1 V1: %x\n", sig1V1.Bytes())
	fmt.Printf("Threshold Sig2 V1: %x\n", sig2V1.Bytes())
	fmt.Printf("Threshold Sig3 V1: %x\n\n", sig3V1.Bytes())

	sigV1, _ := ted25519.Aggregate([]*ted25519.PartialSignature{sig1V1, sig3V1}, &config)
	fmt.Printf("Rebuild signature with share 1 and 3: %x\n\n", sigV1)
	
	
	
	pubKeyData, _ := proto.Marshal(pubKey)
	entry.PubKey = pubKeyData
	
	entry.SignatureV1 = sigV1
	
	entrydata, _ := proto.Marshal(entry)
	fmt.Printf("Entry: %s\n", entry.String())
	fmt.Printf("Signed Entry: %x\n", entrydata)

    /*
	ok, _ := ted25519.Verify(pub, messageV1, sigV1)

	if ok {
		fmt.Printf("\nSignature verified\n\n")
	} else {
		fmt.Printf("\nSignature unverified\n\n")
	}
	*/
	

}
