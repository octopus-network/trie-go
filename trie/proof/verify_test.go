package proof

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ChainSafe/chaindb"
	"github.com/octopus-network/trie-go/scale"
	sub "github.com/octopus-network/trie-go/substrate"
	"github.com/octopus-network/trie-go/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Verify(t *testing.T) {
	t.Parallel()

	leafA := sub.Node{
		PartialKey:   []byte{1},
		StorageValue: []byte{1},
	}

	// leafB is a leaf encoding to more than 32 bytes
	leafB := sub.Node{
		PartialKey:   []byte{2},
		StorageValue: generateBytes(t, 40),
	}
	assertLongEncoding(t, leafB)

	branch := sub.Node{
		PartialKey:   []byte{3, 4},
		StorageValue: []byte{1},
		Children: padRightChildren([]*sub.Node{
			&leafB,
			nil,
			&leafA,
			&leafB,
		}),
	}
	assertLongEncoding(t, branch)

	testCases := map[string]struct {
		encodedProofNodes [][]byte
		rootHash          []byte
		keyLE             []byte
		value             []byte
		errWrapped        error
		errMessage        string
	}{
		"failed building proof trie": {
			rootHash:   []byte{1, 2, 3},
			errWrapped: ErrEmptyProof,
			errMessage: "building trie from proof encoded nodes: " +
				"proof slice empty: for Merkle root hash 0x010203",
		},
		"value not found": {
			encodedProofNodes: [][]byte{
				encodeNode(t, branch),
				encodeNode(t, leafB),
				// Note leaf A is small enough to be inlined in branch
			},
			rootHash:   blake2bNode(t, branch),
			keyLE:      []byte{1, 1}, // nil child of branch
			errWrapped: ErrKeyNotFoundInProofTrie,
			errMessage: "key not found in proof trie: " +
				"0x0101 in proof trie for root hash " +
				"0xec4bb0acfcf778ae8746d3ac3325fc73c3d9b376eb5f8d638dbf5eb462f5e703",
		},
		"key found with nil search value": {
			encodedProofNodes: [][]byte{
				encodeNode(t, branch),
				encodeNode(t, leafB),
				// Note leaf A is small enough to be inlined in branch
			},
			rootHash: blake2bNode(t, branch),
			keyLE:    []byte{0x34, 0x21}, // inlined short leaf of branch
		},
		"key found with mismatching value": {
			encodedProofNodes: [][]byte{
				encodeNode(t, branch),
				encodeNode(t, leafB),
				// Note leaf A is small enough to be inlined in branch
			},
			rootHash:   blake2bNode(t, branch),
			keyLE:      []byte{0x34, 0x21}, // inlined short leaf of branch
			value:      []byte{2},
			errWrapped: ErrValueMismatchProofTrie,
			errMessage: "value found in proof trie does not match: " +
				"expected value 0x02 but got value 0x01 from proof trie",
		},
		"key found with matching value": {
			encodedProofNodes: [][]byte{
				encodeNode(t, branch),
				encodeNode(t, leafB),
				// Note leaf A is small enough to be inlined in branch
			},
			rootHash: blake2bNode(t, branch),
			keyLE:    []byte{0x34, 0x32}, // large hash-referenced leaf of branch
			value:    generateBytes(t, 40),
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := Verify(testCase.encodedProofNodes, testCase.rootHash, testCase.keyLE, testCase.value)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}

func Test_buildTrie(t *testing.T) {
	t.Parallel()

	leafAShort := sub.Node{
		PartialKey:   []byte{1},
		StorageValue: []byte{2},
	}
	assertShortEncoding(t, leafAShort)

	leafBLarge := sub.Node{
		PartialKey:   []byte{2},
		StorageValue: generateBytes(t, 40),
	}
	assertLongEncoding(t, leafBLarge)

	leafCLarge := sub.Node{
		PartialKey:   []byte{3},
		StorageValue: generateBytes(t, 40),
	}
	assertLongEncoding(t, leafCLarge)

	testCases := map[string]struct {
		encodedProofNodes [][]byte
		rootHash          []byte
		expectedTrie      *trie.Trie
		errWrapped        error
		errMessage        string
	}{
		"no proof node": {
			errWrapped: ErrEmptyProof,
			rootHash:   []byte{1},
			errMessage: "proof slice empty: for Merkle root hash 0x01",
		},
		"root node decoding error": {
			encodedProofNodes: [][]byte{
				getBadNodeEncoding(),
			},
			rootHash:   blake2b(t, getBadNodeEncoding()),
			errWrapped: sub.ErrVariantUnknown,
			errMessage: "decoding root node: decoding header: " +
				"decoding header byte: node variant is unknown: " +
				"for header byte 00000001",
		},
		"root proof encoding smaller than 32 bytes": {
			encodedProofNodes: [][]byte{
				encodeNode(t, leafAShort),
			},
			rootHash: blake2bNode(t, leafAShort),
			expectedTrie: trie.NewTrie(&sub.Node{
				PartialKey:   leafAShort.PartialKey,
				StorageValue: leafAShort.StorageValue,
				Dirty:        true,
			}),
		},
		"root proof encoding larger than 32 bytes": {
			encodedProofNodes: [][]byte{
				encodeNode(t, leafBLarge),
			},
			rootHash: blake2bNode(t, leafBLarge),
			expectedTrie: trie.NewTrie(&sub.Node{
				PartialKey:   leafBLarge.PartialKey,
				StorageValue: leafBLarge.StorageValue,
				Dirty:        true,
			}),
		},
		"discard unused node": {
			encodedProofNodes: [][]byte{
				encodeNode(t, leafAShort),
				encodeNode(t, leafBLarge),
			},
			rootHash: blake2bNode(t, leafAShort),
			expectedTrie: trie.NewTrie(&sub.Node{
				PartialKey:   leafAShort.PartialKey,
				StorageValue: leafAShort.StorageValue,
				Dirty:        true,
			}),
		},
		"multiple unordered nodes": {
			encodedProofNodes: [][]byte{
				encodeNode(t, leafBLarge), // chilren 1 and 3
				encodeNode(t, sub.Node{ // root
					PartialKey: []byte{1},
					Children: padRightChildren([]*sub.Node{
						&leafAShort, // inlined
						&leafBLarge, // referenced by Merkle value hash
						&leafCLarge, // referenced by Merkle value hash
						&leafBLarge, // referenced by Merkle value hash
					}),
				}),
				encodeNode(t, leafCLarge), // children 2
			},
			rootHash: blake2bNode(t, sub.Node{
				PartialKey: []byte{1},
				Children: padRightChildren([]*sub.Node{
					&leafAShort,
					&leafBLarge,
					&leafCLarge,
					&leafBLarge,
				}),
			}),
			expectedTrie: trie.NewTrie(&sub.Node{
				PartialKey:  []byte{1},
				Descendants: 4,
				Dirty:       true,
				Children: padRightChildren([]*sub.Node{
					{
						PartialKey:   leafAShort.PartialKey,
						StorageValue: leafAShort.StorageValue,
						Dirty:        true,
					},
					{
						PartialKey:   leafBLarge.PartialKey,
						StorageValue: leafBLarge.StorageValue,
						Dirty:        true,
					},
					{
						PartialKey:   leafCLarge.PartialKey,
						StorageValue: leafCLarge.StorageValue,
						Dirty:        true,
					},
					{
						PartialKey:   leafBLarge.PartialKey,
						StorageValue: leafBLarge.StorageValue,
						Dirty:        true,
					},
				}),
			}),
		},
		"load proof decoding error": {
			encodedProofNodes: [][]byte{
				getBadNodeEncoding(),
				// root with one child pointing to hash of bad encoding above.
				concatBytes([][]byte{
					{0b1000_0000 | 0b0000_0001}, // branch with key size 1
					{1},                         // key
					{0b0000_0001, 0b0000_0000},  // children bitmap
					scaleEncode(t, blake2b(t, getBadNodeEncoding())), // child hash
				}),
			},
			rootHash: blake2b(t, concatBytes([][]byte{
				{0b1000_0000 | 0b0000_0001}, // branch with key size 1
				{1},                         // key
				{0b0000_0001, 0b0000_0000},  // children bitmap
				scaleEncode(t, blake2b(t, getBadNodeEncoding())), // child hash
			})),
			errWrapped: sub.ErrVariantUnknown,
			errMessage: "loading proof: decoding child node for hash digest " +
				"0xcfa21f0ec11a3658d77701b7b1f52fbcb783fe3df662977b6e860252b6c37e1e: " +
				"decoding header: decoding header byte: " +
				"node variant is unknown: for header byte 00000001",
		},
		"root not found": {
			encodedProofNodes: [][]byte{
				encodeNode(t, sub.Node{
					PartialKey:   []byte{1},
					StorageValue: []byte{2},
				}),
			},
			rootHash:   []byte{3},
			errWrapped: ErrRootNodeNotFound,
			errMessage: "root node not found in proof: " +
				"for root hash 0x03 in proof hash digests " +
				"0x60516d0bb6e1bbfb1293f1b276ea9505e9f4a4e7d98f620d05115e0b85274ae1",
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			trie, err := BuildTrie(testCase.encodedProofNodes, testCase.rootHash)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}

			if testCase.expectedTrie != nil {
				require.NotNil(t, trie)
				require.Equal(t, testCase.expectedTrie.String(), trie.String())
			}
			assert.Equal(t, testCase.expectedTrie, trie)
		})
	}
}

func Test_buildTrie2(t *testing.T) {
	// composable parachain data
	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)

	root, err := hex.DecodeString("dc4887669c2a6b3462e9557aa3105a66a02b6ec3b21784613de78c95dc3cbbe0")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("80fffd8028b54b9a0a90d41b7941c43e6a0597d5914e3b62bdcb244851b9fc806c28ea2480d5ba6d50586692888b0c2f5b3c3fc345eb3a2405996f025ed37982ca396f5ed580bd281c12f20f06077bffd56b2f8b6431ee6c9fd11fed9c22db86cea849aeff2280afa1e1b5ce72ea1675e5e69be85e98fbfb660691a76fee9229f758a75315f2bc80aafc60caa3519d4b861e6b8da226266a15060e2071bba4184e194da61dfb208e809d3f6ae8f655009551de95ae1ef863f6771522fd5c0475a50ff53c5c8169b5888024a760a8f6c27928ae9e2fed9968bc5f6e17c3ae647398d8a615e5b2bb4b425f8085a0da830399f25fca4b653de654ffd3c92be39f3ae4f54e7c504961b5bd00cf80c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f08380c644938921d14ae611f3a90991af8b7f5bdb8fa361ee2c646c849bca90f491e6806e729ad43a591cd1321762582782bbe4ed193c6f583ec76013126f7f786e376280509bb016f2887d12137e73d26d7ddcd7f9c8ff458147cb9d309494655fe68de180009f8697d760fbe020564b07f407e6aad58ba9451b3d2d88b3ee03e12db7c47480952dcc0804e1120508a1753f1de4aa5b7481026a3320df8b48e918f0cecbaed3803360bf948fddc403d345064082e8393d7a1aad7a19081f6d02d94358f242b86c")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	t.Log("N1:", n1)

	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20865c4a2b7f010000")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	// Branch 3 with partial key b"", child 15 of root branch
	// Full key is b""
	//nolint:lll
	bytes3, err := hex.DecodeString("8005088076c66e2871b4fe037d112ebffb3bfc8bd83a4ec26047f58ee2df7be4e9ebe3d680c1638f702aaa71e4b78cc8538ecae03e827bb494cc54279606b201ec071a5e24806d2a1e6d5236e1e13c5a5c84831f5f5383f97eba32df6f9faf80e32cf2f129bc")
	require.NoError(t, err)

	n3, err := sub.Decode(bytes.NewReader(bytes3))
	require.NoError(t, err)
	_, _ = n3.CalculateMerkleValue()
	t.Log("N3:", n3)

	proof := [][]byte{
		bytes1, bytes2, bytes3,
	}

	trie, err := BuildTrie(proof, root)
	// t.Log("TRIE:", trie)
	require.NoError(t, err)

	value := trie.Get(key)
	t.Log("The Key Value:", value)
	var timestamp uint64
	err = scale.Unmarshal(value, &timestamp)
	if err != nil {
		panic(err)
	}
	fmt.Printf("timestamp: %d\n", timestamp)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str := time.UnixMilli(int64(timestamp))
	// time_str := time.Unix(int64(timestamp), 0)
	fmt.Printf("timestamp: %s\n", time_str)

	// TODO add a concrete expected value once this test is fixed.
	require.NotEmpty(t, value)
}

func Test_buildTrie3(t *testing.T) {
	// composable parachain data
	//block height = 4900
	//blockhash = 0xa750d21d086d1e54706a0eb52d4beeb75af2dff07afcaacf1c6e1d61c2100e79
	//timestamp = 1,670,565,726,031
	//torage key = 0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb
	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)
	//state root = 0x171ede47def80f78d8859c10fc55154b600fd166b001bb6bf8765c1df62530d3
	root, err := hex.DecodeString("171ede47def80f78d8859c10fc55154b600fd166b001bb6bf8765c1df62530d3")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("808500801b987dbf9f24ce9ce1001e97d33dcfc79920999c37d3ae6b0634497a78da9ced80c1638f702aaa71e4b78cc8538ecae03e827bb494cc54279606b201ec071a5e248084baf221c83784fbee58c383af751a9486978506539c106b37de9d19e62c5130")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	t.Log("N1:", n1)

	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("80ffff8079b6da046c52378a7ba543b5aa141132887428d9adb17d6472011bf4dc8b0a6d80e7ff3f3a8e268349e6feda156d37e76cd011d686f2d04a26bc929faa6b2de68180328d5d55e894aaa8f41735e7a50cce4311565360c596434084f0c8eeb3fbccd580129ff9c4b5740be6b89acdd2dbab3068d5ed42de0a9d78c7aaffff3ecdb52f8d80ee067afaa95d3c8c993586f5ea9607787a037282c8ecc514d5fa0bece67b72928080ef946582b044f23c866c7d48820c383bed0f852e48c813546f4afc97a576b380a437b79067b6b4c40bf4e68e949db74c5030b37f6b3ac92c317551674999c48780a9efe6a803b77fbb7775bfd2199dd568bf3ca792b3cdca82429a5d1873fb329380c9bfdb058843f0432f8b913f4f265234eb1be4df26b1ca778baccea03094fe4d8061ef1e2eb9a4591dcb776a01bd6e4d542028d618bff8d170280c11b695a19ca28073a4d9b8756f41f87c1a62e38595005ec8ee7709148ee8c33cf66095146e6d3b80caf668e367dbd4eaf467a26e86f0e0c192a66e61aba25d6507471a799e2583ce801c66d9d703eaa894a836b8fadd54d4da900a0a5d8c15f2de2e4690ec612771cf8076afaede32fc4fb44bf1a5e1c980d833e4ef4ea0b4657a2487a2dbe5257ecbd9807a5baca4e9c85aac250a04c25f1b2d6c310e28a83d3298ce406fe53b1988e08b80c9ebe8c4d261fd25aaf7fc3e4a03b26bcfa906ae8a97e78ffda8a1963a90d0b3")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	// Branch 3 with partial key b"", child 15 of root branch
	// Full key is b""
	//nolint:lll
	bytes3, err := hex.DecodeString("9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2010f98bf584010000")
	require.NoError(t, err)

	n3, err := sub.Decode(bytes.NewReader(bytes3))
	require.NoError(t, err)
	_, _ = n3.CalculateMerkleValue()
	t.Log("N3:", n3)

	proof := [][]byte{
		bytes1, bytes2, bytes3,
	}

	trie, err := BuildTrie(proof, root)
	// t.Log("TRIE:", trie)
	require.NoError(t, err)

	value := trie.Get(key)
	t.Log("The Key Value:", value)
	var timestamp uint64
	err = scale.Unmarshal(value, &timestamp)
	if err != nil {
		panic(err)
	}
	fmt.Printf("timestamp: %d\n", timestamp)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str := time.UnixMilli(int64(timestamp))
	// // time_str := time.Unix(int64(timestamp), 0)
	fmt.Printf("timestamp: %s\n", time_str)

	// TODO add a concrete expected value once this test is fixed.
	require.NotEmpty(t, value)
}

func Test_buildTrie4(t *testing.T) {
	// composable parachain data
	key, err := hex.DecodeString("08c41974a97dbf15cfbec28365bea2da5e0621c4869aa60c02be9adcc98a0d1d")
	require.NoError(t, err)

	root, err := hex.DecodeString("530d7f7829761fe8d5d6a7491d0bfec238b599995fbb0fc4374a63c1b9c2590d")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("5f0e0621c4869aa60c02be9adcc98a0d1d0d0108020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a10390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	t.Log("N1:", n1)

	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("80101080751598edb99372ee96e97e51c4b12920de4bd8c9c15579c3b52d315ecd7f259280de9bc8146a88d2c43a27c51d859b79fe0978cb449a7eec0099a7b0b700b96367")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	// Branch 3 with partial key b"", child 15 of root branch
	// Full key is b""
	//nolint:lll
	bytes3, err := hex.DecodeString("804001808f555192d233d23287109c58713abcff53d517a44669ecc9f1b07d91c0fa440980fc2ef28fbd46ddd7c42f006ceb2eaeb8ceaad8fe09657231f816cfc21786da94")
	require.NoError(t, err)

	n3, err := sub.Decode(bytes.NewReader(bytes3))
	require.NoError(t, err)
	_, _ = n3.CalculateMerkleValue()
	t.Log("N3:", n3)

	bytes4, err := hex.DecodeString("80ffbe80b426a9e5c88d14588f6ef2fa103714d6916b240065d8e8da3e5e1cc3e6710b4280f1d004806f011e6f792c2e794b8c77ac2a360a33b55f5d186acbff28a96042f58002a863f9ce9149380a0299f64d252a06421c23c6f0a4fbd822120d3e1fdcc3fb80823896f2488f926b8c4376d65d6879244433e72f5a6c6754e296d1d4d663d7c0803298a18710d5dbe277f8807acb66711c83e7e389697be25bda6e7a2497c28c5a80032c044a257f8cdea0910f07404b6affd801ed41b5f92d2741798bbad46499ea80f1089dc8969501efbf50b94482eab81f24657e4c3aaf7c78077736cef4034d7c80b1f4de7c3ac5665016d561a60659cd2d8f2d3e0a97e2ea9749279bd8e35eb1f18069afa784f1e33e03abe0de46c9d796d33f7b9e7f0bfd1450b640243695d7207d80ed92b63809a2a874b54328294ee4086bfc4c1d2b227203b6fe0da08c2139e90480ef74282e32f18b4178d875d71156e560fea146a099de663941c700fd7dca6b21800dd4873b8bd4dd57f321cb5849798976cb2ef7ccd4cd9c1afcbf41106a9cfb8880f71c624f55c6909f01cade3142d0c18c0eb2c67815405716bc8071acc2f800788095a4b3cd3c52c569bea4f2119c009b00f787f1531d9ee4164ec964bd30d776c0")
	require.NoError(t, err)

	n4, err := sub.Decode(bytes.NewReader(bytes4))
	require.NoError(t, err)
	_, _ = n4.CalculateMerkleValue()
	t.Log("N4:", n4)

	bytes5, err := hex.DecodeString("9d041974a97dbf15cfbec28365bea2da3005505f0e7b9012096b41c4eb3aaf947f6ea4290800008051b37e412ebb4ccf319a0ced502241963efe91a19506007ce479b2276dd353c2685f0f05bccc2f70ec66a32999c5761156be203b0000000000000080009186629eba38667903184a814e20a33af3926785282f36d8bf68f0c32d7a16")
	require.NoError(t, err)

	n5, err := sub.Decode(bytes.NewReader(bytes5))
	require.NoError(t, err)
	_, _ = n4.CalculateMerkleValue()
	t.Log("N4:", n5)

	proof := [][]byte{
		bytes1, bytes2, bytes3, bytes4, bytes5,
	}

	trie1, err := BuildTrie(proof, root)
	// t.Log("TRIE:", trie)
	require.NoError(t, err)

	value := trie1.Get(key)
	t.Log("Value from proof:", value)
	// var timestamp uint64
	// err = scale.Unmarshal(value, &timestamp)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("timestamp: %d\n", timestamp)
	// // time_str := time.UnixMicro(int64(timestamp))
	// time_str := time.UnixMilli(int64(timestamp))
	// // // time_str := time.Unix(int64(timestamp), 0)
	// fmt.Printf("timestamp: %s\n", time_str)

	// TODO add a concrete expected value once this test is fixed.
	require.NotEmpty(t, value)

	// verify testing
	trie2 := trie.NewEmptyTrie()
	database, err := chaindb.NewBadgerDB(&chaindb.Config{
		InMemory: true,
	})
	require.NoError(t, err)

	err = trie2.WriteDirty(database)
	require.NoError(t, err)

	err = Verify(proof, root, key, value)
	require.NoError(t, err)
}

func Test_buildTrie5(t *testing.T) {
	//astar data
	//block height : 2,502,278
	//block hash : 0x8b68ab67b365669803e4d61e84773d51bc701047e6c5e795fa7f3c3aceef0599
	// stateRoot: 0xf22cccdc8e6ec676feaa98a11a00ea4be778eee3ee3c932fce123420ae8f275f
	//encoded storage key
	// 0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb
	//3: state.getStorage: StorageData
	// 0xcf90af0f85010000
	//timestamp.now: u64
	// 1,671,005,442,255

	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)

	root, err := hex.DecodeString("f22cccdc8e6ec676feaa98a11a00ea4be778eee3ee3c932fce123420ae8f275f")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("80fffa80858bc2a0101d60ed17b72862dc325ccc3166479c6f42c8b40efaea455da55eef8038184dd577bfdcaeb1aac46b3b133fb291ac569726851abef4f78eb4b8f3832980efc2598f6a51c464ca11b8292c91c8aaa1423e81b69be2917c6eede365a9c3bf80ad74fedecda93568b32288ee19e9070a7bfedd7ba908f70f8488fb9b2942c7b080a4dc8a4762bdcdb9c218a05e3d736b7b841f6b43416348e7d1fa1da243e1d36980b8c7bbea7b80adccb43bfeabc3404b8e5ea9bfd38489d15a0d364262c7c6d76380ee8f61b9f838f96531cfc3d993ba46e7d7112f06501e9ecba4c921616e585c2080c48a21cb310ebf7b8ac396beebf4daf2460e3acb21e9257761ce4aaedb9345fa808f1fd39b1c0600dd95bc150237d86b8b583118ea3c760d2e873338242d672c5e80bd03756919c080d6f206c2b99d4fdb0e37c8d305ce0c0ee8350bd4e2aea6f51b801131c53f05d71d5646d916bd7cfe9cf202187d585f95e69f3cbd272cc89eac418085ba31b59e40c53c4a00a0c0fbe984b967dbe21550d448db14547f644946cfeb80a889835bb7b755b52804c9e5cbcf5b917fa3713a3d6da21cf01b291d841368d880d03e0f4aa0ff9a22a9e1a8df4f52fba3721a9b55981c9530a052cfede8056247")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	t.Log("N1:", n1)

	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20cf90af0f85010000")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	// Branch 3 with partial key b"", child 15 of root branch
	// Full key is b""
	//nolint:lll
	// bytes3, err := hex.DecodeString("8005088076c66e2871b4fe037d112ebffb3bfc8bd83a4ec26047f58ee2df7be4e9ebe3d680c1638f702aaa71e4b78cc8538ecae03e827bb494cc54279606b201ec071a5e24806d2a1e6d5236e1e13c5a5c84831f5f5383f97eba32df6f9faf80e32cf2f129bc")
	// require.NoError(t, err)

	// n3, err := node.Decode(bytes.NewReader(bytes3))
	// require.NoError(t, err)
	// _, _ = n3.CalculateMerkleValue()
	// t.Log("N3:", n3)

	proof := [][]byte{
		bytes1, bytes2,
	}

	trie, err := BuildTrie(proof, root)
	// t.Log("TRIE:", trie)
	require.NoError(t, err)

	value := trie.Get(key)
	t.Log("The Key Value:", value)
	var timestamp uint64
	err = scale.Unmarshal(value, &timestamp)
	if err != nil {
		panic(err)
	}
	fmt.Printf("timestamp: %d\n", timestamp)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str := time.UnixMilli(int64(timestamp))
	// time_str := time.Unix(int64(timestamp), 0)
	fmt.Printf("timestamp: %s\n", time_str)

	// TODO add a concrete expected value once this test is fixed.
	require.NotEmpty(t, value)
}

func Test_loadProof(t *testing.T) {
	t.Parallel()

	largeValue := generateBytes(t, 40)

	leafLarge := sub.Node{
		PartialKey:   []byte{3},
		StorageValue: largeValue,
	}
	assertLongEncoding(t, leafLarge)

	testCases := map[string]struct {
		merkleValueToEncoding map[string][]byte
		node                  *sub.Node
		expectedNode          *sub.Node
		errWrapped            error
		errMessage            string
	}{
		"leaf node": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
			},
		},
		"branch node with child hash not found": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{3}},
				}),
			},
			merkleValueToEncoding: map[string][]byte{},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Dirty:        true,
			},
		},
		"branch node with child hash found": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}},
				}),
			},
			merkleValueToEncoding: map[string][]byte{
				string([]byte{2}): encodeNode(t, sub.Node{
					PartialKey:   []byte{3},
					StorageValue: []byte{1},
				}),
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{
						PartialKey:   []byte{3},
						StorageValue: []byte{1},
						Dirty:        true,
					},
				}),
			},
		},
		"branch node with one child hash found and one not found": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  2,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}}, // found
					{NodeValue: []byte{3}}, // not found
				}),
			},
			merkleValueToEncoding: map[string][]byte{
				string([]byte{2}): encodeNode(t, sub.Node{
					PartialKey:   []byte{3},
					StorageValue: []byte{1},
				}),
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{
						PartialKey:   []byte{3},
						StorageValue: []byte{1},
						Dirty:        true,
					},
				}),
			},
		},
		"branch node with branch child hash": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  2,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}},
				}),
			},
			merkleValueToEncoding: map[string][]byte{
				string([]byte{2}): encodeNode(t, sub.Node{
					PartialKey:   []byte{3},
					StorageValue: []byte{1},
					Children: padRightChildren([]*sub.Node{
						{PartialKey: []byte{4}, StorageValue: []byte{2}},
					}),
				}),
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  3,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{
						PartialKey:   []byte{3},
						StorageValue: []byte{1},
						Dirty:        true,
						Descendants:  1,
						Children: padRightChildren([]*sub.Node{
							{
								PartialKey:   []byte{4},
								StorageValue: []byte{2},
								Dirty:        true,
							},
						}),
					},
				}),
			},
		},
		"child decoding error": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}},
				}),
			},
			merkleValueToEncoding: map[string][]byte{
				string([]byte{2}): getBadNodeEncoding(),
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{2},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}},
				}),
			},
			errWrapped: sub.ErrVariantUnknown,
			errMessage: "decoding child node for hash digest 0x02: " +
				"decoding header: decoding header byte: node variant is unknown: " +
				"for header byte 00000001",
		},
		"grand child": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{1},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}},
				}),
			},
			merkleValueToEncoding: map[string][]byte{
				string([]byte{2}): encodeNode(t, sub.Node{
					PartialKey:   []byte{2},
					StorageValue: []byte{2},
					Descendants:  1,
					Dirty:        true,
					Children: padRightChildren([]*sub.Node{
						&leafLarge, // encoded to hash
					}),
				}),
				string(blake2bNode(t, leafLarge)): encodeNode(t, leafLarge),
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{1},
				Descendants:  2,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{
						PartialKey:   []byte{2},
						StorageValue: []byte{2},
						Descendants:  1,
						Dirty:        true,
						Children: padRightChildren([]*sub.Node{
							{
								PartialKey:   leafLarge.PartialKey,
								StorageValue: leafLarge.StorageValue,
								Dirty:        true,
							},
						}),
					},
				}),
			},
		},

		"grand child load proof error": {
			node: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{1},
				Descendants:  1,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{NodeValue: []byte{2}},
				}),
			},
			merkleValueToEncoding: map[string][]byte{
				string([]byte{2}): encodeNode(t, sub.Node{
					PartialKey:   []byte{2},
					StorageValue: []byte{2},
					Descendants:  1,
					Dirty:        true,
					Children: padRightChildren([]*sub.Node{
						&leafLarge, // encoded to hash
					}),
				}),
				string(blake2bNode(t, leafLarge)): getBadNodeEncoding(),
			},
			expectedNode: &sub.Node{
				PartialKey:   []byte{1},
				StorageValue: []byte{1},
				Descendants:  2,
				Dirty:        true,
				Children: padRightChildren([]*sub.Node{
					{
						PartialKey:   []byte{2},
						StorageValue: []byte{2},
						Descendants:  1,
						Dirty:        true,
						Children: padRightChildren([]*sub.Node{
							{
								NodeValue: blake2bNode(t, leafLarge),
							},
						}),
					},
				}),
			},
			errWrapped: sub.ErrVariantUnknown,
			errMessage: "decoding child node for hash digest " +
				"0x6888b9403129c11350c6054b46875292c0ffedcfd581e66b79bdf350b775ebf2: " +
				"decoding header: decoding header byte: node variant is unknown: " +
				"for header byte 00000001",
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := LoadProof(testCase.merkleValueToEncoding, testCase.node)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}

			assert.Equal(t, testCase.expectedNode.String(), testCase.node.String())
		})
	}
}

func Test_bytesToString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		b []byte
		s string
	}{
		"nil slice": {
			s: "nil",
		},
		"empty slice": {
			b: []byte{},
			s: "0x",
		},
		"small slice": {
			b: []byte{1, 2, 3},
			s: "0x010203",
		},
		"big slice": {
			b: []byte{
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
			},
			s: "0x0001020304050607...0203040506070809",
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := bytesToString(testCase.b)

			assert.Equal(t, testCase.s, s)
		})
	}
}
