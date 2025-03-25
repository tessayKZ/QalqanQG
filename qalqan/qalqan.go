package qalqan

/*key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // etalon key
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

data := []uint8{0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // etalon data
		 		 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
res := make([]uint8, 16)
data2 := make([]uint8, 16)

qalqan.Kexp(key, 32, 16, rkey111)
qalqan.Encrypt(data, rkey111, 32, 16, res)  // [255 247 218 248 163 247 226 11 36 110 25 52 4 11 163 120] - etalon encrypted data
qalqan.DecryptOFB(res, rkey111, 32, 16, data2) // [16 17 34 51 68 85 102 119 136 153 170 187 204 221 238 255] - etalon decrypted data*/

import (
	"fmt"
	"io"
	"unsafe"
)

const (
	KEXPSHIFT       = 17
	RKEYLEN         = 16
	BLOCKLEN        = 16
	MAXBLOCKLEN     = 64
	MINKEYLEN       = 32
	MAXKEYLEN       = 128
	KEYLENSTEP      = 16
	MAXEXPKLEN      = 1024
	DEFAULT_KEY_LEN = 32
	EXPKLEN         = 272
)

/* Lin 32, Dif 4, PZh 7, deg 112, SAC 120 */
var sb = [256]byte{
	0xd1, 0xb5, 0xa6, 0x74, 0x2f, 0xb2, 0x03, 0x77, 0xae, 0xb3, 0x60, 0x95, 0xfd, 0xf8, 0xc7, 0xf0,
	0x2b, 0xce, 0xa5, 0x91, 0x4c, 0x6f, 0xf3, 0x4f, 0x82, 0x01, 0x45, 0x76, 0x9f, 0xed, 0x41, 0xfb,
	0xac, 0x4e, 0x5e, 0x04, 0xeb, 0xf9, 0xf1, 0x3a, 0x1f, 0xe2, 0x8e, 0xe7, 0x85, 0x35, 0xdb, 0x52,
	0x78, 0xa1, 0xfc, 0xa2, 0xde, 0x68, 0x02, 0x4d, 0xf6, 0xdd, 0xcf, 0xa3, 0xdc, 0x6b, 0x81, 0x44,
	0x2a, 0x5d, 0x1e, 0xe0, 0x53, 0x71, 0x3b, 0xc1, 0xcc, 0x9d, 0x80, 0xd5, 0x84, 0x00, 0x24, 0x4b,
	0xb6, 0x83, 0x0d, 0x87, 0x7e, 0x86, 0xca, 0x96, 0xbe, 0x5a, 0xe6, 0xd0, 0xd4, 0xd8, 0x55, 0xc0,
	0x05, 0xe5, 0xe9, 0x5b, 0x47, 0xe4, 0x2d, 0x34, 0x13, 0x88, 0x48, 0x32, 0x38, 0xb9, 0xda, 0xc9,
	0x42, 0x29, 0xd7, 0xf2, 0x9b, 0x6d, 0xe8, 0x8d, 0x12, 0x7c, 0x8c, 0x3f, 0xbc, 0x3c, 0x1b, 0xc5,
	0x69, 0x22, 0x97, 0xaa, 0x73, 0x0a, 0x0c, 0x8a, 0x90, 0x31, 0xc4, 0x33, 0xe1, 0x8b, 0x9c, 0x63,
	0x5f, 0xf5, 0xf7, 0xff, 0x79, 0x49, 0xd3, 0xc6, 0x7b, 0x1a, 0x39, 0xc8, 0x6e, 0x72, 0xd9, 0xc3,
	0x62, 0x28, 0xbd, 0xbb, 0xfa, 0x2e, 0xbf, 0x43, 0x06, 0x0b, 0x7a, 0x64, 0x5c, 0x92, 0x37, 0x3d,
	0x66, 0x26, 0x51, 0xef, 0x0f, 0xa9, 0x14, 0x70, 0x16, 0x17, 0x10, 0x19, 0x93, 0x09, 0x59, 0x15,
	0xfe, 0x4a, 0xcb, 0x2c, 0xcd, 0xb8, 0x94, 0xab, 0xdf, 0xa7, 0x0e, 0x30, 0xaf, 0x56, 0x23, 0xb1,
	0xb0, 0x58, 0x7d, 0xc2, 0x1d, 0x50, 0x20, 0x61, 0x25, 0x89, 0xa0, 0x6c, 0x11, 0x54, 0x98, 0xb7,
	0x18, 0x21, 0xad, 0x3e, 0xd2, 0xea, 0x40, 0xd6, 0xf4, 0xa4, 0x8f, 0xa8, 0x08, 0x57, 0xba, 0xee,
	0x75, 0x6a, 0x07, 0x99, 0x7f, 0x1c, 0xe3, 0x46, 0x67, 0xec, 0x27, 0x36, 0xb4, 0x65, 0x9e, 0x9a,
}

var isb = [256]byte{
	0x4d, 0x19, 0x36, 0x06, 0x23, 0x60, 0xa8, 0xf2, 0xec, 0xbd, 0x85, 0xa9, 0x86, 0x52, 0xca, 0xb4,
	0xba, 0xdc, 0x78, 0x68, 0xb6, 0xbf, 0xb8, 0xb9, 0xe0, 0xbb, 0x99, 0x7e, 0xf5, 0xd4, 0x42, 0x28,
	0xd6, 0xe1, 0x81, 0xce, 0x4e, 0xd8, 0xb1, 0xfa, 0xa1, 0x71, 0x40, 0x10, 0xc3, 0x66, 0xa5, 0x04,
	0xcb, 0x89, 0x6b, 0x8b, 0x67, 0x2d, 0xfb, 0xae, 0x6c, 0x9a, 0x27, 0x46, 0x7d, 0xaf, 0xe3, 0x7b,
	0xe6, 0x1e, 0x70, 0xa7, 0x3f, 0x1a, 0xf7, 0x64, 0x6a, 0x95, 0xc1, 0x4f, 0x14, 0x37, 0x21, 0x17,
	0xd5, 0xb2, 0x2f, 0x44, 0xdd, 0x5e, 0xcd, 0xed, 0xd1, 0xbe, 0x59, 0x63, 0xac, 0x41, 0x22, 0x90,
	0x0a, 0xd7, 0xa0, 0x8f, 0xab, 0xfd, 0xb0, 0xf8, 0x35, 0x80, 0xf1, 0x3d, 0xdb, 0x75, 0x9c, 0x15,
	0xb7, 0x45, 0x9d, 0x84, 0x03, 0xf0, 0x1b, 0x07, 0x30, 0x94, 0xaa, 0x98, 0x79, 0xd2, 0x54, 0xf4,
	0x4a, 0x3e, 0x18, 0x51, 0x4c, 0x2c, 0x55, 0x53, 0x69, 0xd9, 0x87, 0x8d, 0x7a, 0x77, 0x2a, 0xea,
	0x88, 0x13, 0xad, 0xbc, 0xc6, 0x0b, 0x57, 0x82, 0xde, 0xf3, 0xff, 0x74, 0x8e, 0x49, 0xfe, 0x1c,
	0xda, 0x31, 0x33, 0x3b, 0xe9, 0x12, 0x02, 0xc9, 0xeb, 0xb5, 0x83, 0xc7, 0x20, 0xe2, 0x08, 0xcc,
	0xd0, 0xcf, 0x05, 0x09, 0xfc, 0x01, 0x50, 0xdf, 0xc5, 0x6d, 0xee, 0xa3, 0x7c, 0xa2, 0x58, 0xa6,
	0x5f, 0x47, 0xd3, 0x9f, 0x8a, 0x7f, 0x97, 0x0e, 0x9b, 0x6f, 0x56, 0xc2, 0x48, 0xc4, 0x11, 0x3a,
	0x5b, 0x00, 0xe4, 0x96, 0x5c, 0x4b, 0xe7, 0x72, 0x5d, 0x9e, 0x6e, 0x2e, 0x3c, 0x39, 0x34, 0xc8,
	0x43, 0x8c, 0x29, 0xf6, 0x65, 0x61, 0x5a, 0x2b, 0x76, 0x62, 0xe5, 0x24, 0xf9, 0x1d, 0xef, 0xb3,
	0x0f, 0x26, 0x73, 0x16, 0xe8, 0x91, 0x38, 0x92, 0x0d, 0x25, 0xa4, 0x1f, 0x32, 0x0c, 0xc0, 0x93,
}

func RNDS(x uint32) uint32 {
	return 16 + (x-32)/16
}

func Kexp(key []byte, klen int, blen int, rkey []byte) {
	var r0 [17]byte
	var r1 [15]byte
	addk := klen - 32
	step := 0
	s := KEXPSHIFT
	for i := range 15 {
		r0[i] = key[2*i]
		r1[i] = key[2*i+1]
	}
	r0[15] = key[30]
	r0[16] = key[31]
	for r := range int(RNDS(uint32(klen))) {
		for k := range blen + s {
			t0 := sb[r0[0]] + r0[1] + sb[r0[3]] + r0[7] + sb[r0[12]] + r0[16]
			t1 := sb[r1[0]] + r1[3] + sb[r1[9]] + r1[12] + sb[r1[14]]
			for i := range 14 {
				r0[i] = r0[i+1]
				r1[i] = r1[i+1]
			}
			r0[14] = r0[15]
			r0[15] = r0[16]
			if k >= s {
				rkey[r*blen+k-s] = t0 + r1[4]
				if step < addk {
					if (step & 1) == 1 {
						t0 += key[32+step]
					} else {
						t1 += key[32+step]
					}
					step++
				}
			}
			r0[16] = t0
			r1[14] = t1
		}
		s = 0 // 0 -20, 1 - 53
	}
}

func ROTL(x uint32, s uint32) uint32 {
	s &= 31
	return (x << s) | (x >> (32 - s))
}

func ROTL64(x uint64, s uint64) uint64 {
	s &= 63
	return (x << s) | (x >> (64 - s))
}

func Lin344(din, dout []uint32, c0 []uint32) {
	if len(din) < 4 || len(dout) < 4 || len(c0) < 3 {
		panic("Ошибка: недостаточный размер входных данных в Llin344")
	}
	dout[0] = din[0] ^ ROTL(din[1], c0[0]) ^ ROTL(din[2], c0[1]) ^ ROTL(din[3], c0[2])
	dout[1] = din[1] ^ ROTL(din[2], c0[0]) ^ ROTL(din[3], c0[1]) ^ ROTL(dout[0], c0[2])
	dout[2] = din[2] ^ ROTL(din[3], c0[0]) ^ ROTL(dout[0], c0[1]) ^ ROTL(dout[1], c0[2])
	dout[3] = din[3] ^ ROTL(dout[0], c0[0]) ^ ROTL(dout[1], c0[1]) ^ ROTL(dout[2], c0[2])
}

func Lin384(din, dout []uint32, c1 []uint32) {
	dout[0] = din[0] ^ ROTL(din[1], c1[0]) ^ ROTL(din[2], c1[1]) ^ ROTL(din[3], c1[2]) ^ ROTL(din[4], c1[3]) ^ ROTL(din[5], c1[4]) ^ ROTL(din[6], c1[5]) ^ ROTL(din[7], c1[6])
	dout[1] = din[1] ^ ROTL(din[2], c1[0]) ^ ROTL(din[3], c1[1]) ^ ROTL(din[4], c1[2]) ^ ROTL(din[5], c1[3]) ^ ROTL(din[6], c1[4]) ^ ROTL(din[7], c1[5]) ^ ROTL(dout[0], c1[6])
	dout[2] = din[2] ^ ROTL(din[3], c1[0]) ^ ROTL(din[4], c1[1]) ^ ROTL(din[5], c1[2]) ^ ROTL(din[6], c1[3]) ^ ROTL(din[7], c1[4]) ^ ROTL(dout[0], c1[5]) ^ ROTL(dout[1], c1[6])
	dout[3] = din[3] ^ ROTL(din[4], c1[0]) ^ ROTL(din[5], c1[1]) ^ ROTL(din[6], c1[2]) ^ ROTL(din[7], c1[3]) ^ ROTL(dout[0], c1[4]) ^ ROTL(dout[1], c1[5]) ^ ROTL(dout[2], c1[6])
	dout[4] = din[4] ^ ROTL(din[5], c1[0]) ^ ROTL(din[6], c1[1]) ^ ROTL(din[7], c1[2]) ^ ROTL(dout[0], c1[3]) ^ ROTL(dout[1], c1[4]) ^ ROTL(dout[2], c1[5]) ^ ROTL(dout[3], c1[6])
	dout[5] = din[5] ^ ROTL(din[6], c1[0]) ^ ROTL(din[7], c1[1]) ^ ROTL(dout[0], c1[2]) ^ ROTL(dout[1], c1[3]) ^ ROTL(dout[2], c1[4]) ^ ROTL(dout[3], c1[5]) ^ ROTL(dout[4], c1[6])
	dout[6] = din[6] ^ ROTL(din[7], c1[0]) ^ ROTL(dout[0], c1[1]) ^ ROTL(dout[1], c1[2]) ^ ROTL(dout[2], c1[3]) ^ ROTL(dout[3], c1[4]) ^ ROTL(dout[4], c1[5]) ^ ROTL(dout[5], c1[6])
	dout[7] = din[7] ^ ROTL(dout[0], c1[0]) ^ ROTL(dout[1], c1[1]) ^ ROTL(dout[2], c1[2]) ^ ROTL(dout[3], c1[3]) ^ ROTL(dout[4], c1[4]) ^ ROTL(dout[5], c1[5]) ^ ROTL(dout[6], c1[6])
}

func Lin388(din, dout []uint64, c2 []uint64) {
	dout[0] = din[0] ^ ROTL64(din[1], c2[0]) ^ ROTL64(din[2], c2[1]) ^ ROTL64(din[3], c2[2]) ^ ROTL64(din[4], c2[3]) ^ ROTL64(din[5], c2[4]) ^ ROTL64(din[6], c2[5]) ^ ROTL64(din[7], c2[6])
	dout[1] = din[1] ^ ROTL64(din[2], c2[0]) ^ ROTL64(din[3], c2[1]) ^ ROTL64(din[4], c2[2]) ^ ROTL64(din[5], c2[3]) ^ ROTL64(din[6], c2[4]) ^ ROTL64(din[7], c2[5]) ^ ROTL64(dout[0], c2[6])
	dout[2] = din[2] ^ ROTL64(din[3], c2[0]) ^ ROTL64(din[4], c2[1]) ^ ROTL64(din[5], c2[2]) ^ ROTL64(din[6], c2[3]) ^ ROTL64(din[7], c2[4]) ^ ROTL64(dout[0], c2[5]) ^ ROTL64(dout[1], c2[6])
	dout[3] = din[3] ^ ROTL64(din[4], c2[0]) ^ ROTL64(din[5], c2[1]) ^ ROTL64(din[6], c2[2]) ^ ROTL64(din[7], c2[3]) ^ ROTL64(dout[0], c2[4]) ^ ROTL64(dout[1], c2[5]) ^ ROTL64(dout[2], c2[6])
	dout[4] = din[4] ^ ROTL64(din[5], c2[0]) ^ ROTL64(din[6], c2[1]) ^ ROTL64(din[7], c2[2]) ^ ROTL64(dout[0], c2[3]) ^ ROTL64(dout[1], c2[4]) ^ ROTL64(dout[2], c2[5]) ^ ROTL64(dout[3], c2[6])
	dout[5] = din[5] ^ ROTL64(din[6], c2[0]) ^ ROTL64(din[7], c2[1]) ^ ROTL64(dout[0], c2[2]) ^ ROTL64(dout[1], c2[3]) ^ ROTL64(dout[2], c2[4]) ^ ROTL64(dout[3], c2[5]) ^ ROTL64(dout[4], c2[6])
	dout[6] = din[6] ^ ROTL64(din[7], c2[0]) ^ ROTL64(dout[0], c2[1]) ^ ROTL64(dout[1], c2[2]) ^ ROTL64(dout[2], c2[3]) ^ ROTL64(dout[3], c2[4]) ^ ROTL64(dout[4], c2[5]) ^ ROTL64(dout[5], c2[6])
	dout[7] = din[7] ^ ROTL64(dout[0], c2[0]) ^ ROTL64(dout[1], c2[1]) ^ ROTL64(dout[2], c2[2]) ^ ROTL64(dout[3], c2[3]) ^ ROTL64(dout[4], c2[4]) ^ ROTL64(dout[5], c2[5]) ^ ROTL64(dout[6], c2[6])
}

func LinOp(d, r unsafe.Pointer, blocklen int) {
	switch blocklen {
	case 16:
		Lin344((*[4]uint32)(d)[:], (*[4]uint32)(r)[:], []uint32{1, 17, 14}) // c0
	case 32:
		Lin384((*[8]uint32)(d)[:], (*[8]uint32)(r)[:], []uint32{3, 5, 11, 21, 16, 30, 19}) // c1
	case 64:
		Lin388((*[8]uint64)(d)[:], (*[8]uint64)(r)[:], []uint64{4, 0, 22, 27, 47, 4, 61}) // c2
	default:
		panic("unexpected block length")
	}
}

func InvlinOp(d, r unsafe.Pointer, blocklen int) {
	switch blocklen {
	case 16:
		Ilin344((*[4]uint32)(d)[:], (*[4]uint32)(r)[:], []uint32{1, 17, 14}) // c0
	case 32:
		Ilin384((*[8]uint32)(d)[:], (*[8]uint32)(r)[:], []uint32{3, 5, 11, 21, 16, 30, 19}) // c1
	case 64:
		Ilin388((*[8]uint64)(d)[:], (*[8]uint64)(r)[:], []uint64{4, 0, 22, 27, 47, 4, 61}) // c2
	default:
		panic("unexpected block length")
	}
}

func sBox(data, res []uint8, blen int, sb []byte) {
	for i := range blen {
		res[i] = sb[data[i]]
	}
}

func AddRkX(block, rkey []uint8, nr, blen int, res []uint8) {
	for i := range blen {
		res[i] = block[i] ^ rkey[nr*blen+i]
	}
}

func AddRk(block, rkey []uint8, nr, blen int, res []uint8) {
	tmp := uint16(block[0]) + uint16(rkey[blen*nr])
	res[0] = uint8(tmp)
	tmp >>= 8
	for i := 1; i < blen; i++ {
		tmp += uint16(block[i]) + uint16(rkey[blen*nr+i])
		res[i] = uint8(tmp)
		tmp >>= 8
	}
}

func Encrypt(data, rkey []uint8, klen int, blen int, res []uint8) {
	var block [MAXBLOCKLEN]uint8
	var block2 [MAXBLOCKLEN]uint8
	AddRk(data, rkey, 0, blen, block[:])
	sBox(block[:], block2[:], blen, sb[:])
	LinOp(unsafe.Pointer(&block2[0]), unsafe.Pointer(&block[0]), blen)
	for i := 1; i < int(RNDS(uint32(klen)))-1; i++ {
		AddRkX(block[:], rkey, i, blen, block2[:])
		sBox(block2[:], block2[:], blen, sb[:])
		LinOp(unsafe.Pointer(&block2[0]), unsafe.Pointer(&block[0]), blen)
	}
	AddRk(block[:], rkey, int(RNDS(uint32(klen)))-1, blen, res)
}

func InvAddRk(block, rkey []uint8, nr int, blen int) []uint8 {
	res := make([]byte, BLOCKLEN)
	var tmp int = int(block[0]) - int(rkey[blen*nr])
	res[0] = uint8(tmp)
	tmp = tmp >> 8
	for i := 1; i < blen; i++ {
		tmp += int(block[i]) - int(rkey[blen*nr+i])
		res[i] = uint8(tmp)
		tmp = tmp >> 8
	}
	return res[:]
}

func Ilin344(din, dout []uint32, c0 []uint32) {
	{
		dout[3] = din[3] ^ ROTL(din[0], c0[0]) ^ ROTL(din[1], c0[1]) ^ ROTL(din[2], c0[2])
		dout[2] = din[2] ^ ROTL(dout[3], c0[0]) ^ ROTL(din[0], c0[1]) ^ ROTL(din[1], c0[2])
		dout[1] = din[1] ^ ROTL(dout[2], c0[0]) ^ ROTL(dout[3], c0[1]) ^ ROTL(din[0], c0[2])
		dout[0] = din[0] ^ ROTL(dout[1], c0[0]) ^ ROTL(dout[2], c0[1]) ^ ROTL(dout[3], c0[2])
	}
}

func Ilin384(din, dout []uint32, c1 []uint32) {
	dout[7] = din[7] ^ ROTL(din[0], c1[0]) ^ ROTL(din[1], c1[1]) ^ ROTL(din[2], c1[2]) ^ ROTL(din[3], c1[3]) ^ ROTL(din[4], c1[4]) ^ ROTL(din[5], c1[5]) ^ ROTL(din[6], c1[6])
	dout[6] = din[6] ^ ROTL(dout[7], c1[0]) ^ ROTL(din[0], c1[1]) ^ ROTL(din[1], c1[2]) ^ ROTL(din[2], c1[3]) ^ ROTL(din[3], c1[4]) ^ ROTL(din[4], c1[5]) ^ ROTL(din[5], c1[6])
	dout[5] = din[5] ^ ROTL(dout[6], c1[0]) ^ ROTL(dout[7], c1[1]) ^ ROTL(din[0], c1[2]) ^ ROTL(din[1], c1[3]) ^ ROTL(din[2], c1[4]) ^ ROTL(din[3], c1[5]) ^ ROTL(din[4], c1[6])
	dout[4] = din[4] ^ ROTL(dout[5], c1[0]) ^ ROTL(dout[6], c1[1]) ^ ROTL(dout[7], c1[2]) ^ ROTL(din[0], c1[3]) ^ ROTL(din[1], c1[4]) ^ ROTL(din[2], c1[5]) ^ ROTL(din[3], c1[6])
	dout[3] = din[3] ^ ROTL(dout[4], c1[0]) ^ ROTL(dout[5], c1[1]) ^ ROTL(dout[6], c1[2]) ^ ROTL(dout[7], c1[3]) ^ ROTL(din[0], c1[4]) ^ ROTL(din[1], c1[5]) ^ ROTL(din[2], c1[6])
	dout[2] = din[2] ^ ROTL(dout[3], c1[0]) ^ ROTL(dout[4], c1[1]) ^ ROTL(dout[5], c1[2]) ^ ROTL(dout[6], c1[3]) ^ ROTL(dout[7], c1[4]) ^ ROTL(din[0], c1[5]) ^ ROTL(din[1], c1[6])
	dout[1] = din[1] ^ ROTL(dout[2], c1[0]) ^ ROTL(dout[3], c1[1]) ^ ROTL(dout[4], c1[2]) ^ ROTL(dout[5], c1[3]) ^ ROTL(dout[6], c1[4]) ^ ROTL(dout[7], c1[5]) ^ ROTL(din[0], c1[6])
	dout[0] = din[0] ^ ROTL(dout[1], c1[0]) ^ ROTL(dout[2], c1[1]) ^ ROTL(dout[3], c1[2]) ^ ROTL(dout[4], c1[3]) ^ ROTL(dout[5], c1[4]) ^ ROTL(dout[6], c1[5]) ^ ROTL(dout[7], c1[6])
}

func Ilin388(din, dout []uint64, c2 []uint64) {
	dout[7] = din[7] ^ ROTL64(din[0], c2[0]) ^ ROTL64(din[1], c2[1]) ^ ROTL64(din[2], c2[2]) ^ ROTL64(din[3], c2[3]) ^ ROTL64(din[4], c2[4]) ^ ROTL64(din[5], c2[5]) ^ ROTL64(din[6], c2[6])
	dout[6] = din[6] ^ ROTL64(dout[7], c2[0]) ^ ROTL64(din[0], c2[1]) ^ ROTL64(din[1], c2[2]) ^ ROTL64(din[2], c2[3]) ^ ROTL64(din[3], c2[4]) ^ ROTL64(din[4], c2[5]) ^ ROTL64(din[5], c2[6])
	dout[5] = din[5] ^ ROTL64(dout[6], c2[0]) ^ ROTL64(dout[7], c2[1]) ^ ROTL64(din[0], c2[2]) ^ ROTL64(din[1], c2[3]) ^ ROTL64(din[2], c2[4]) ^ ROTL64(din[3], c2[5]) ^ ROTL64(din[4], c2[6])
	dout[4] = din[4] ^ ROTL64(dout[5], c2[0]) ^ ROTL64(dout[6], c2[1]) ^ ROTL64(dout[7], c2[2]) ^ ROTL64(din[0], c2[3]) ^ ROTL64(din[1], c2[4]) ^ ROTL64(din[2], c2[5]) ^ ROTL64(din[3], c2[6])
	dout[3] = din[3] ^ ROTL64(dout[4], c2[0]) ^ ROTL64(dout[5], c2[1]) ^ ROTL64(dout[6], c2[2]) ^ ROTL64(dout[7], c2[3]) ^ ROTL64(din[0], c2[4]) ^ ROTL64(din[1], c2[5]) ^ ROTL64(din[2], c2[6])
	dout[2] = din[2] ^ ROTL64(dout[3], c2[0]) ^ ROTL64(dout[4], c2[1]) ^ ROTL64(dout[5], c2[2]) ^ ROTL64(dout[6], c2[3]) ^ ROTL64(dout[7], c2[4]) ^ ROTL64(din[0], c2[5]) ^ ROTL64(din[1], c2[6])
	dout[1] = din[1] ^ ROTL64(dout[2], c2[0]) ^ ROTL64(dout[3], c2[1]) ^ ROTL64(dout[4], c2[2]) ^ ROTL64(dout[5], c2[3]) ^ ROTL64(dout[6], c2[4]) ^ ROTL64(dout[7], c2[5]) ^ ROTL64(din[0], c2[6])
	dout[0] = din[0] ^ ROTL64(dout[1], c2[0]) ^ ROTL64(dout[2], c2[1]) ^ ROTL64(dout[3], c2[2]) ^ ROTL64(dout[4], c2[3]) ^ ROTL64(dout[5], c2[4]) ^ ROTL64(dout[6], c2[5]) ^ ROTL64(dout[7], c2[6])
}

func InvsBox(data, res []uint8, blen int) { // 32 ops
	for i := range blen {
		res[i] = isb[data[i]]
	}
}

func DecryptOFB(data []uint8, rkey []uint8, klen int, blen int, res []uint8) {
	var block [MAXBLOCKLEN]uint8
	var block2 [MAXBLOCKLEN]uint8
	copy(block[:], InvAddRk(data, rkey, int(RNDS(uint32(klen))-1), blen))
	for i := int(RNDS(uint32(klen))) - 2; i > 0; i-- {
		InvlinOp(unsafe.Pointer(&block), unsafe.Pointer(&block2), blen)
		InvsBox(block2[:], block2[:], blen)
		AddRkX(block2[:], rkey, i, blen, block[:])
	}
	InvlinOp(unsafe.Pointer(&block), unsafe.Pointer(&block2), blen)
	InvsBox(block2[:], block2[:], blen)
	copy(res, InvAddRk(block2[:], rkey, 0, blen))
}

/* Функция осуществляет дополнение нулями до значения кратного 16 */
func myappend(buf []byte, len int) {
	add_len := BLOCKLEN - len
	if add_len == 0 {
		buf[15] = 0x01
		buf[0] = 0x80
		for i := 1; i < BLOCKLEN-1; i++ {
			buf[i] = 0x00
		}
	} else if add_len == 1 {
		buf[15] = 0x81
	} else {
		buf[15] = 0x01
		buf[len] = 0x80
		for i := 1; i < add_len-1; i++ {
			buf[len+i] = 0x00
		}
	}
}

func EncryptOFB_File(dataLen int, rKey []byte, iv []byte, ostream io.Reader, sstream io.Writer) {
	modLen := dataLen % BLOCKLEN
	tmpBuf := make([]byte, BLOCKLEN)
	cipherBuf := make([]byte, BLOCKLEN)
	clearBuf := make([]byte, BLOCKLEN)

	if modLen == 0 {
		sstream.Write(iv)
		Encrypt(iv, rKey, DEFAULT_KEY_LEN, BLOCKLEN, tmpBuf)
		copy(cipherBuf, tmpBuf)
		ostream.Read(clearBuf)
		for i := range BLOCKLEN {
			cipherBuf[i] = cipherBuf[i] ^ clearBuf[i]
		}
		sstream.Write(cipherBuf)
		for i := BLOCKLEN; i < dataLen; i += BLOCKLEN {
			ostream.Read(clearBuf)
			Encrypt(tmpBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, cipherBuf)
			copy(tmpBuf, cipherBuf)
			for j := 0; j < BLOCKLEN; j++ {
				cipherBuf[j] = cipherBuf[j] ^ clearBuf[j]
			}
			sstream.Write(cipherBuf)
		}
		if dataLen != BLOCKLEN {
			resbuf := make([]byte, BLOCKLEN)
			myappend(resbuf, BLOCKLEN)
			Encrypt(tmpBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, cipherBuf)
			for j := 0; j < BLOCKLEN; j++ {
				cipherBuf[j] = cipherBuf[j] ^ resbuf[j]
			}
			sstream.Write(cipherBuf)
		}
	}
	if modLen < BLOCKLEN {
		sstream.Write(iv)
		Encrypt(iv, rKey, DEFAULT_KEY_LEN, BLOCKLEN, tmpBuf)
		copy(cipherBuf, tmpBuf)
		ostream.Read(clearBuf)
		myappend(clearBuf, int(modLen))
		for i := range BLOCKLEN {
			cipherBuf[i] = cipherBuf[i] ^ clearBuf[i]
		}
		sstream.Write(cipherBuf)
	}
	if modLen != 0 && modLen > BLOCKLEN {
		sstream.Write(iv)
		Encrypt(iv, rKey, DEFAULT_KEY_LEN, BLOCKLEN, tmpBuf)
		copy(cipherBuf, tmpBuf)
		ostream.Read(clearBuf)
		for i := range BLOCKLEN {
			cipherBuf[i] = cipherBuf[i] ^ clearBuf[i]
		}
		sstream.Write(cipherBuf)
		for i := BLOCKLEN; i < dataLen-modLen; i += BLOCKLEN {
			ostream.Read(clearBuf)
			Encrypt(tmpBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, cipherBuf)
			copy(tmpBuf, cipherBuf)
			for j := 0; j < BLOCKLEN; j++ {
				cipherBuf[j] = cipherBuf[j] ^ clearBuf[j]
			}
			sstream.Write(cipherBuf)
		}
		ostream.Read(clearBuf[:modLen])
		myappend(clearBuf, int(modLen))

		Encrypt(tmpBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, cipherBuf)
		for j := 0; j < BLOCKLEN; j++ {
			cipherBuf[j] = cipherBuf[j] ^ clearBuf[j]
		}
		sstream.Write(cipherBuf)
	}
}

func DecryptOFB_File(dataLen int, rKey []byte, iv []byte, ostream io.Reader, sstream io.Writer) error {
	modLen := dataLen % BLOCKLEN
	tmpBuf := make([]byte, BLOCKLEN)
	cipherBuf := make([]byte, BLOCKLEN)
	clearBuf := make([]byte, BLOCKLEN)

	Encrypt(iv, rKey, DEFAULT_KEY_LEN, BLOCKLEN, tmpBuf)

	for i := 0; i < dataLen-modLen; i += BLOCKLEN {
		if _, err := io.ReadFull(ostream, cipherBuf); err != nil {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}

		for j := 0; j < BLOCKLEN; j++ {
			clearBuf[j] = cipherBuf[j] ^ tmpBuf[j]
		}

		if _, err := sstream.Write(clearBuf); err != nil {
			return fmt.Errorf("failed to write decrypted data: %w", err)
		}

		Encrypt(tmpBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, tmpBuf)
	}

	if modLen > 0 {
		partialBuf := make([]byte, BLOCKLEN)
		_, err := io.ReadFull(ostream, partialBuf[:modLen])
		if err != nil {
			return fmt.Errorf("failed to read final block: %w", err)
		}

		Encrypt(tmpBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, tmpBuf)

		for j := 0; j < modLen; j++ {
			clearBuf[j] = partialBuf[j] ^ tmpBuf[j]
		}

		if _, err := sstream.Write(clearBuf[:modLen]); err != nil {
			return fmt.Errorf("failed to write final decrypted block: %w", err)
		}
	}

	return nil
}

func Qalqan_Imit(dataLen uint64, rKey []byte, ostream io.Reader, imit []uint8) {
	modLen := dataLen % BLOCKLEN
	var buf [BLOCKLEN]uint8
	var cypherbuf [BLOCKLEN]uint8
	if modLen == 0 {
		ostream.Read(buf[:BLOCKLEN])
		Encrypt(buf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
		for i := uint64(BLOCKLEN); i < dataLen; i += BLOCKLEN {
			ostream.Read(buf[:BLOCKLEN])
			for j := 0; j < BLOCKLEN; j++ {
				cypherbuf[j] ^= buf[j]
			}
			Encrypt(cypherbuf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
		}
	} else if modLen != 0 {
		ostream.Read(buf[:BLOCKLEN])
		Encrypt(buf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
		for i := uint64(BLOCKLEN); i < dataLen-modLen; i += BLOCKLEN {
			ostream.Read(buf[:BLOCKLEN])
			for j := 0; j < BLOCKLEN; j++ {
				cypherbuf[j] ^= buf[j]
			}
			Encrypt(cypherbuf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
		}
		ostream.Read(buf[:modLen])
		myappend(buf[:], int(modLen))
		for j := 0; j < BLOCKLEN; j++ {
			cypherbuf[j] ^= buf[j]
		}
		Encrypt(cypherbuf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
	}
	copy(imit[:BLOCKLEN], cypherbuf[:BLOCKLEN])
}

func Qalqan_ImitData(dataLen uint64, rKey []byte, indata []uint8, imit []uint8) {
	modLen := dataLen % BLOCKLEN
	var buf [BLOCKLEN]uint8
	var cypherbuf [BLOCKLEN]uint8

	if modLen == 0 {
		copy(buf[:], indata[:BLOCKLEN])
		Encrypt(buf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])

		for i := uint64(BLOCKLEN); i < dataLen; i += BLOCKLEN {
			copy(buf[:], indata[i:i+BLOCKLEN])
			for j := 0; j < BLOCKLEN; j++ {
				cypherbuf[j] ^= buf[j]
			}
			Encrypt(cypherbuf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
		}
	} else {
		copy(buf[:], indata[:BLOCKLEN])
		Encrypt(buf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])

		var i uint64
		for i = BLOCKLEN; i < dataLen-modLen; i += BLOCKLEN {
			copy(buf[:], indata[i:i+BLOCKLEN])
			for j := 0; j < BLOCKLEN; j++ {
				cypherbuf[j] ^= buf[j]
			}
			Encrypt(cypherbuf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
		}

		copy(buf[:modLen], indata[i:i+modLen])
		myappend(buf[:], int(modLen))
		for j := 0; j < BLOCKLEN; j++ {
			cypherbuf[j] ^= buf[j]
		}
		Encrypt(cypherbuf[:], rKey, DEFAULT_KEY_LEN, BLOCKLEN, cypherbuf[:])
	}

	copy(imit[:BLOCKLEN], cypherbuf[:BLOCKLEN])
}

/* Функция осуществляет удаление нулевых значений, дополненных до значения кратного 16 */
func Myremove(buf *uint8) int {
	var i int
	bufSlice := (*[BLOCKLEN]uint8)(unsafe.Pointer(buf))[:]
	if bufSlice[BLOCKLEN-1] != 0x01 {
		if bufSlice[BLOCKLEN-1] == 0x81 {
			return BLOCKLEN - 1
		} else {
			return BLOCKLEN
		}
	}
	for i = BLOCKLEN - 2; i >= 0 && bufSlice[i] == 0; i-- {
		if bufSlice[i] != 0x80 {
			return BLOCKLEN
		}
	}
	return i
}

/*func DecryptECB_data(dataLen int, rKey []byte, ostream io.Reader, res []byte) {
	cipherBuf := make([]byte, BLOCKLEN)
	clearBuf := make([]byte, BLOCKLEN)

	for i := 0; i < dataLen; i += BLOCKLEN {
		ostream.Read(cipherBuf)
		Decrypt(cipherBuf, rKey, DEFAULT_KEY_LEN, BLOCKLEN, cipherBuf)
		for j := 0; j < BLOCKLEN; j++ {
			res[i+j] = clearBuf[j]
		}
	}

}*/
