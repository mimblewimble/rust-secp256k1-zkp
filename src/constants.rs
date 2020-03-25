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
pub const BULLET_PROOF_MSG_SIZE: usize = 20;

/// The order of the secp256k1 curve
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
];

/// Generator point G
///
/// Used as generator point for the blinding factor in Pedersen Commitments.
/// Definition: Standard generator point of secp256k1
/// (as defined in http://www.secg.org/sec2-v2.pdf)
///
/// Format: x- and y- coordinate, without compressed/uncompressed prefix byte
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

/// Generator point H
///
/// Used as generator point for the value in Pedersen Commitments.
/// Created as NUMS (nothing-up-my-sleeve) curve point from SHA256 hash of G.
/// Details: Calculate sha256 of uncompressed serialization format of G, treat the
/// result as x-coordinate, find the first point on  curve with this x-coordinate
/// (which happens to exist on the curve)
///
/// Example in SageMath:
/// --------------------
/// sage: import hashlib
///
/// sage: # finite field of secp256k1:
/// sage: F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
/// sage: # Elliptic Curve defined by y^2 = x^3 + 0x + 7 over finite field F ( = secp256k1)
/// sage: secp256k1 = EllipticCurve ([F (0), F (7)])
///
/// sage: # hash of generator point G in uncompressed form:
/// sage: hash_of_g =  hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex'))
/// sage: hash_of_g_as_int = Integer(int(hash_of_g.hexdigest(),16))
///
/// sage: # get the first point on the curve (if any exists) from given x-coordinate:
/// sage: POINT_H = secp256k1.lift_x(hash_of_g_as_int)
///
/// sage: # output x- and y-coordinates of the point in hexadecimal:
/// sage: '%x %x'%POINT_H.xy()
///
/// sage Result: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904'
///
/// Format: x- and y- coordinate, without compressed/uncompressed prefix byte
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

/// Generator point J
///
/// Used as generator point in Switch Commitments.
/// Created as NUMS (nothing-up-my-sleeve) curve point from double-SHA256 hash of G.
/// Details: Calculate sha256 of sha256 of uncompressed serialization format of G, treat
/// the result as x-coordinate, find the first point on curve with this x-coordinate
/// (which happens to exist on the curve)
///
/// Example in SageMath:
/// --------------------
/// sage: import hashlib
///
/// sage: # finite field of secp256k1:
/// sage: F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
/// sage: # Elliptic Curve defined by y^2 = x^3 + 0x + 7 over finite field F ( = secp256k1)
/// sage: secp256k1 = EllipticCurve ([F (0), F (7)])
///
/// sage: # hash of generator point G in uncompressed form:
/// sage: hash_of_g =  hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex'))
///
/// sage: # double hash of generator point G:
/// sage: double_hash_of_g = hashlib.sha256(hash_of_g.hexdigest().decode('hex'))
/// sage: # treat as Integer
/// sage: double_hash_as_int = Integer(int(double_hash_of_g.hexdigest(),16))
///
/// sage: # get the first point on the curve (if any exists) from given x-coordinate:
/// sage: POINT_J = secp256k1.lift_x(double_hash_as_int)
///
/// sage: # output x- and y-coordinates of the point in hexadecimal:
/// sage: '%x %x'%POINT_J.xy()
///
/// sage Result: 'b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f a43f09d32caa8f53423f427403a56a3165a5a69a74cf56fc5901a2dca6c5c43a'
///
/// Format:
/// raw x- and y- coordinate, without compressed/uncompressed prefix byte
/// in REVERSED byte order (indicated by the suffix "_RAW")!
///
/// This is different from G and H as in the underlying secp256k1 library, J is
/// declared as "secp256k1_pubkey" while G and H are declared as "secp256k1_generator"
/// which seem to be represented and parsed differently (see "secp256k1_ec_pubkey_parse" vs
/// "secp256k1_generator_parse" in https://github.com/mimblewimble/secp256k1-zkp/).
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
