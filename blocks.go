package gokeepasslib

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Block size of 1MB - https://keepass.info/help/kb/kdbx_4.html#dataauth
const blockSplitRate = 1048576

var (
	errHMACVerificationFailed = errors.New("failed to verify HMAC")
)

// ErrInvalidContentBlock is returned if the content blocks of a database file
// cannot be read, e.g. because the file is truncated or corrupted.
var ErrInvalidContentBlock = errors.New(
	"gokeepasslib: invalid content block, the database file is truncated or corrupted",
)

type BlockHMACBuilder struct {
	baseKey []byte
}

func NewBlockHMACBuilder(masterSeed []byte, transformedKey []byte) *BlockHMACBuilder {
	keyBuilder := sha512.New()
	keyBuilder.Write(masterSeed)
	keyBuilder.Write(transformedKey)
	keyBuilder.Write([]byte{0x01})
	baseKey := keyBuilder.Sum(nil)

	return &BlockHMACBuilder{
		baseKey: baseKey,
	}
}

func (b *BlockHMACBuilder) BuildHMAC(index uint64, length uint32, data []byte) []byte {
	blockKeyBuilder := sha512.New()
	binary.Write(blockKeyBuilder, binary.LittleEndian, index)
	blockKeyBuilder.Write(b.baseKey)
	blockKey := blockKeyBuilder.Sum(nil)

	mac := hmac.New(sha256.New, blockKey)
	binary.Write(mac, binary.LittleEndian, index)
	binary.Write(mac, binary.LittleEndian, length)
	mac.Write(data)
	return mac.Sum(nil)
}

// decomposeContentBlocks4 decodes the content data block by block (Kdbx v4)
// Used to extract data blocks from the entire content
func decomposeContentBlocks4(
	r io.Reader,
	masterSeed []byte,
	transformedKey []byte,
) ([]byte, error) {
	var contentData []byte
	// Get all the content
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	hmacBuilder := NewBlockHMACBuilder(masterSeed, transformedKey)

	index := uint64(0)
	offset := 0
	for {
		// Every block starts with its HMAC and its length
		if len(content)-offset < 32+4 {
			return nil, fmt.Errorf("%w: block %d is incomplete", ErrInvalidContentBlock, index)
		}

		var blockHMAC [32]byte
		copy(blockHMAC[:], content[offset:offset+32])
		offset += 32

		length := binary.LittleEndian.Uint32(content[offset : offset+4])
		offset += 4

		// The length is checked against the remaining content before allocating
		// anything, since a damaged length could be up to 4 GiB
		if uint64(length) > uint64(len(content)-offset) {
			return nil, fmt.Errorf(
				"%w: block %d claims %d bytes, but only %d are left",
				ErrInvalidContentBlock, index, length, len(content)-offset,
			)
		}

		data := content[offset : offset+int(length)]
		offset += int(length)

		calculatedHMAC := hmacBuilder.BuildHMAC(index, length, data)

		if subtle.ConstantTimeCompare(calculatedHMAC, blockHMAC[:]) == 0 {
			return nil, fmt.Errorf("%w for block %d", errHMACVerificationFailed, index)
		}

		if length == 0 {
			break
		}

		// Add to blocks
		contentData = append(contentData, data...)

		index++
	}
	return contentData, nil
}

// decomposeContentBlocks31 decodes the content data block by block (Kdbx v3.1)
// Used to extract data blocks from the entire content
func decomposeContentBlocks31(r io.Reader) ([]byte, error) {
	var contentData []byte
	// Get all the content
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	index := uint32(0)
	offset := 0
	for {
		// Every block starts with its index, its hash and its length
		if len(content)-offset < 4+32+4 {
			return nil, fmt.Errorf("%w: block %d is incomplete", ErrInvalidContentBlock, index)
		}

		blockIndex := binary.LittleEndian.Uint32(content[offset : offset+4])
		offset += 4
		if blockIndex != index {
			return nil, fmt.Errorf(
				"%w: expected block %d, found block %d",
				ErrInvalidContentBlock, index, blockIndex,
			)
		}

		var hash [32]byte
		copy(hash[:], content[offset:offset+32])
		offset += 32

		length := binary.LittleEndian.Uint32(content[offset : offset+4])
		offset += 4

		if length == 0 {
			// The final block has no data and an empty hash
			if hash != [32]byte{} {
				return nil, fmt.Errorf("%w: final block %d has a hash", ErrInvalidContentBlock, index)
			}
			break
		}

		// The length is checked against the remaining content before allocating
		// anything, since a damaged length could be up to 4 GiB
		if uint64(length) > uint64(len(content)-offset) {
			return nil, fmt.Errorf(
				"%w: block %d claims %d bytes, but only %d are left",
				ErrInvalidContentBlock, index, length, len(content)-offset,
			)
		}

		data := content[offset : offset+int(length)]
		offset += int(length)

		if sha256.Sum256(data) != hash {
			return nil, fmt.Errorf("%w: hash of block %d does not match", ErrInvalidContentBlock, index)
		}

		// Add to decoded blocks
		contentData = append(contentData, data...)

		index++
	}
	return contentData, nil
}

// composeContentBlocks4 composes every content block into a HMAC-LENGTH-DATA block scheme (Kdbx v4)
func composeContentBlocks4(
	w io.Writer,
	contentData []byte,
	masterSeed []byte,
	transformedKey []byte,
) {
	hmacBuilder := NewBlockHMACBuilder(masterSeed, transformedKey)

	var offset int
	var endOffset int
	var index = uint64(0)
	for {
		remainingLength := len(contentData[offset:])

		if remainingLength >= blockSplitRate {
			endOffset = offset + blockSplitRate
		} else {
			endOffset = offset + remainingLength
		}

		length := endOffset - offset
		data := make([]byte, length)
		copy(data, contentData[offset:endOffset])
		uLength := uint32(length)

		blockHMAC := hmacBuilder.BuildHMAC(index, uLength, data)

		w.Write(blockHMAC)
		binary.Write(w, binary.LittleEndian, uLength)
		w.Write(data)

		offset = endOffset

		if length == 0 {
			break
		}

		index++
	}
	binary.Write(w, binary.LittleEndian, [32]byte{})
	binary.Write(w, binary.LittleEndian, uint32(0))
}

// composeBlocks31 composes every content block
// into a INDEX-SHA-LENGTH-DATA block scheme (Kdbx v3.1)
func composeContentBlocks31(w io.Writer, contentData []byte) {
	index := uint32(0)
	offset := 0
	for offset < len(contentData) {
		var hash [32]byte
		var endOffset int

		if len(contentData[offset:]) >= blockSplitRate {
			endOffset = offset + blockSplitRate
		} else {
			endOffset = len(contentData)
		}

		data := contentData[offset:endOffset]
		length := uint32(len(data))
		hash = sha256.Sum256(data)

		binary.Write(w, binary.LittleEndian, index)
		binary.Write(w, binary.LittleEndian, hash)
		binary.Write(w, binary.LittleEndian, length)
		binary.Write(w, binary.LittleEndian, data)
		index++
		offset = endOffset
	}
	binary.Write(w, binary.LittleEndian, index)
	binary.Write(w, binary.LittleEndian, [32]byte{})
	binary.Write(w, binary.LittleEndian, uint32(0))
}
