package criptus

import (
	"bytes"
	"testing"
)

func TestPKCS7PaddingAndUnpadding(t *testing.T) {
	testCases := []struct {
		name       string
		input      []byte
		blockSize  int
		wantPadded []byte
	}{
		{
			name:       "Exact Block Size",
			input:      []byte("1234567890123456"),
			blockSize:  16,
			wantPadded: append([]byte("1234567890123456"), bytes.Repeat([]byte{byte(16)}, 16)...),
		},
		{
			name:       "Needs Padding",
			input:      []byte("12345"),
			blockSize:  8,
			wantPadded: append([]byte("12345"), bytes.Repeat([]byte{byte(3)}, 3)...),
		},
		{
			name:       "Empty Input",
			input:      []byte(""),
			blockSize:  8,
			wantPadded: bytes.Repeat([]byte{byte(8)}, 8),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := PKCS7Padding(tc.input, tc.blockSize)

			if !bytes.Equal(padded, tc.wantPadded) {
				t.Errorf("PKCS7Padding() = %v, want %v", padded, tc.wantPadded)
			}

			unpadded := PKCS7UnPadding(padded)
			if !bytes.Equal(unpadded, tc.input) {
				t.Errorf("PKCS7UnPadding() = %v, want %v", unpadded, tc.input)
			}
		})
	}
}

func TestPKCS5PaddingAndUnpadding(t *testing.T) {
	testCases := []struct {
		name       string
		input      []byte
		blockSize  int
		wantPadded []byte
	}{
		{
			name:       "Exact Block Size",
			input:      []byte("12345678"),
			blockSize:  8,
			wantPadded: append([]byte("12345678"), bytes.Repeat([]byte{byte(8)}, 8)...),
		},
		{
			name:       "Needs Padding",
			input:      []byte("12345"),
			blockSize:  8,
			wantPadded: append([]byte("12345"), bytes.Repeat([]byte{byte(3)}, 3)...),
		},
		{
			name:       "Empty Input",
			input:      []byte(""),
			blockSize:  8,
			wantPadded: bytes.Repeat([]byte{byte(8)}, 8),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs5Padding(tc.input, tc.blockSize)
			if !bytes.Equal(padded, tc.wantPadded) {
				t.Errorf("pkcs5Padding() = %v, want %v", padded, tc.wantPadded)
			}

			unpadded := pkcs5UnPadding(padded)
			if !bytes.Equal(unpadded, tc.input) {
				t.Errorf("pkcs5UnPadding() = %v, want %v", unpadded, tc.input)
			}
		})
	}
}
