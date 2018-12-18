// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Constants
//! Constants related to the API and the underlying curve

/// The size (in bytes) of a message
pub const MESSAGE_SIZE: usize = 32;

/// The size (in bytes) of a secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a public key array. This only needs to be 65
/// but must be 72 for compatibility with the `ArrayVec` library.
pub const PUBLIC_KEY_SIZE: usize = 72;

/// The size (in bytes) of an uncompressed public key
pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;

/// The size (in bytes) of a compressed public key
pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

/// The size of an agg sig
pub const AGG_SIGNATURE_SIZE: usize = 64;
 
/// The maximum size of a signature
pub const MAX_SIGNATURE_SIZE: usize = 72;

/// The maximum size of a compact signature
pub const COMPACT_SIGNATURE_SIZE: usize = 64;

/// The size of a generator point
pub const GENERATOR_SIZE: usize = 64;

/// The size of a Pedersen commitment
pub const PEDERSEN_COMMITMENT_SIZE: usize = 33;

/// The size of a Pedersen commitment
pub const PEDERSEN_COMMITMENT_SIZE_INTERNAL: usize = 64;

/// The size of a single Bullet proof
pub const SINGLE_BULLET_PROOF_SIZE: usize = 675;

#[cfg(feature = "bullet-proof-sizing")]
pub const MAX_PROOF_SIZE: usize = SINGLE_BULLET_PROOF_SIZE;
/// The max size of a range proof
#[cfg(not(feature = "bullet-proof-sizing"))]
pub const MAX_PROOF_SIZE: usize = 5134;

/// The maximum size of a message embedded in a range proof
#[cfg(not(feature = "bullet-proof-sizing"))]
pub const PROOF_MSG_SIZE: usize = 2048;
#[cfg(feature = "bullet-proof-sizing")]
pub const PROOF_MSG_SIZE: usize = 2048;

/// The maximum size of an optional message embedded in a bullet proof
pub const BULLET_PROOF_MSG_SIZE: usize = 16;

/// The order of the secp256k1 curve
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
];

/// Generator G
pub const GENERATOR_G : [u8;64] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
];

/// Generator H (as compressed curve point (3))
pub const GENERATOR_H : [u8;64] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
    0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
    0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
];

/// Raw bytes for generator J as public key
/// This is the sha256 of the sha256 of 'g' after DER encoding (without compression),
/// which happens to be a point on the curve.
/// sage: gen_h =  hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex'))
/// sage: gen_j_input = gen_h.hexdigest()
/// sage: gen_j =  hashlib.sha256(gen_j_input.decode('hex'))
/// sage: G3 = EllipticCurve ([F (0), F (7)]).lift_x(int(gen_j.hexdigest(),16))
/// sage: '%x %x'%G3.xy()
pub const GENERATOR_PUB_J_RAW : [u8;64] = [
    0x5f, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2a,
    0x8d, 0x8b, 0x39, 0x7e, 0x9b, 0xf4, 0x54, 0x29,
    0x2f, 0x5a, 0x1b, 0x3d, 0x38, 0x85, 0x16, 0xc2,
    0xf3, 0x03, 0xfc, 0x95, 0x67, 0xf5, 0x60, 0xb8,
    0x3a, 0xc4, 0xc5, 0xa6, 0xdc, 0xa2, 0x01, 0x59,
    0xfc, 0x56, 0xcf, 0x74, 0x9a, 0xa6, 0xa5, 0x65,
    0x31, 0x6a, 0xa5, 0x03, 0x74, 0x42, 0x3f, 0x42,
    0x53, 0x8f, 0xaa, 0x2c, 0xd3, 0x09, 0x3f, 0xa4
];