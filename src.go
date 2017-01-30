package balloon

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/sha3"
	"hash"
)

const (
	DELTA     = 3
	SALT_SIZE = 32
)

type Blocks [][]byte

func Appends(blocks ...[]byte) (p []byte) {
	for _, block := range blocks {
		p = append(p, block...)
	}
	return
}

func Uint64Bytes(x int) []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, uint64(x))
	return p
}

func GenerateSalt() []byte {
	salt := make([]byte, SALT_SIZE)
	n, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	if n != SALT_SIZE {
		panic(fmt.Sprintf("Only read %d of %d bytes\n", n, SALT_SIZE))
	}
	return salt
}

func BalloonHash(password, salt []byte, size, spaceCost, timeCost int) []byte {
	blocks := make(Blocks, spaceCost)
	count := 1
	var hash hash.Hash
	switch size {
	case 224:
		hash = sha3.New224()
	case 256:
		hash = sha3.New256()
	case 384:
		hash = sha3.New384()
	case 512:
		hash = sha3.New512()
	default:
		panic(fmt.Sprintf("Unsupported hash size: %d bits", size))
	}
	hash.Write(Appends(Uint64Bytes(count), password, salt))
	blocks[0] = hash.Sum(nil)
	for i := 1; i < spaceCost; i++ {
		count++
		hash.Reset()
		hash.Write(Appends(Uint64Bytes(count), blocks[i-1]))
		blocks[i] = hash.Sum(nil)
	}
	for i := 0; i < timeCost; i++ {
		for j := 0; j < spaceCost; j++ {
			count++
			hash.Reset()
			if j == 0 {
				hash.Write(Appends(Uint64Bytes(count), blocks[spaceCost-1], blocks[j]))
			} else {
				hash.Write(Appends(Uint64Bytes(count), blocks[j-1], blocks[j]))
			}
			blocks[j] = hash.Sum(nil)
			for k := 0; k < DELTA; k++ {
				hash.Reset()
				hash.Write(Appends(Uint64Bytes(i), Uint64Bytes(j), Uint64Bytes(k)))
				p := hash.Sum(nil)
				count++
				hash.Reset()
				hash.Write(Appends(Uint64Bytes(count), salt, p))
				n := int(binary.BigEndian.Uint64(hash.Sum(nil)) % uint64(spaceCost))
				count++
				hash.Reset()
				hash.Write(Appends(Uint64Bytes(count), blocks[j], blocks[n]))
				blocks[j] = hash.Sum(nil)
			}
		}
	}
	return blocks[spaceCost-1]
}
