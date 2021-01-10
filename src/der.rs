//! Handlers for DER serialization.

/// DER types that we care about.
enum DerType {
    Explicit(u8),
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    Oid,
    Utf8String,
    Sequence,
    Set,
    UtcTime,
    GeneralizedTime,
}

impl DerType {
    /// Returns the class, encoding, and type number for this type.
    pub(super) fn parts(&self) -> (u8, u8, u8) {
        match self {
            // Context-specific | Constructed | EOC
            DerType::Explicit(typ) => (2, 1, *typ),
            // Universal | Primitive | BOOLEAN
            DerType::Boolean => (0, 0, 1),
            // Universal | Primitive | INTEGER
            DerType::Integer => (0, 0, 2),
            // Universal | Primitive | BIT STRING
            DerType::BitString => (0, 0, 3),
            // Universal | Primitive | OCTET STRING
            DerType::OctetString => (0, 0, 4),
            // Universal | Primitive | NULL
            DerType::Null => (0, 0, 5),
            // Universal | Primitive | OBJECT IDENTIFIER
            DerType::Oid => (0, 0, 6),
            // Universal | Primitive | UTF8String
            DerType::Utf8String => (0, 0, 12),
            // Universal | Constructed | SEQUENCE
            DerType::Sequence => (0, 1, 16),
            // Universal | Constructed | SET
            DerType::Set => (0, 1, 17),
            // Universal | Both | UTCTime
            DerType::UtcTime => (0, 0, 23),
            // Universal | Both | GeneralizedTime
            DerType::GeneralizedTime => (0, 0, 24),
        }
    }
}

/// A trait for objects which represent ASN.1 object identifiers.
pub trait Oid: AsRef<[u64]> {}

impl Oid for &'static [u64] {}

impl<T> Oid for &T where T: Oid {}

/// DER serialization APIs.
pub mod write {
    use chrono::{DateTime, Utc};
    use cookie_factory::{
        bytes::be_u8,
        combinator::{cond, slice, string},
        gen_simple,
        multi::all,
        sequence::{pair, tuple, Tuple},
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::{DerType, Oid};

    /// Encodes an ASN.1 type.
    fn der_type<W: Write>(typ: DerType) -> impl SerializeFn<W> {
        let (class, pc, num) = typ.parts();

        be_u8((class << 6) | (pc << 5) | num)
    }

    /// Encodes an ASN.1 length using DER.
    fn der_length<W: Write>(len: usize) -> impl SerializeFn<W> {
        // DER: Must use definite form.
        pair(
            // Short form
            cond(len < 128, be_u8(len as u8)),
            // Long form
            cond(len >= 128, move |w: WriteContext<W>| {
                // DER: Must encode in the minimum number of octets.
                let len_bytes = len.to_be_bytes();
                let mut len_slice = &len_bytes[..];
                while !len_slice.is_empty() && len_slice[0] == 0 {
                    len_slice = &len_slice[1..];
                }
                // This will always hold for usize.
                assert!(len_slice.len() < 127);

                // Binding forces len_slice to be dropped before len_bytes.
                let res = pair(be_u8((1 << 7) | (len_slice.len() as u8)), slice(len_slice))(w)?;
                Ok(res)
            }),
        )
    }

    /// Encodes an ASN.1 data value using DER.
    fn der_tlv<W: Write, Gen>(typ: DerType, ser_content: Gen) -> impl SerializeFn<W>
    where
        Gen: SerializeFn<Vec<u8>>,
    {
        // We serialize the content into a temporary buffer to determine its length.
        let content = gen_simple(ser_content, vec![]).expect("can serialize into Vec");

        tuple((der_type(typ), der_length(content.len()), slice(content)))
    }

    /// Serializes the given value if it is not equal to its default.
    pub fn der_default<W: Write, Gen, F, T>(inner: F, val: T, default: T) -> impl SerializeFn<W>
    where
        Gen: SerializeFn<W>,
        F: FnOnce(T) -> Gen,
        T: PartialEq,
    {
        cond(val != default, inner(val))
    }

    /// Wraps an ASN.1 data value in an EXPLICIT marker.
    ///
    /// TODO: Find a specification reference for this.
    pub fn der_explicit<W: Write, Gen>(typ: u8, inner: Gen) -> impl SerializeFn<W>
    where
        Gen: SerializeFn<Vec<u8>>,
    {
        der_tlv(DerType::Explicit(typ), inner)
    }

    /// Encodes a boolean as an ASN.1 BOOLEAN using DER.
    ///
    /// From X.690 section 11.1:
    /// ```text
    /// If the encoding represents the boolean value TRUE, its single contents octet shall
    /// have all eight bits set to one.
    /// ```
    pub fn der_boolean<W: Write>(val: bool) -> impl SerializeFn<W> {
        der_tlv(DerType::Boolean, slice(if val { &[0xff] } else { &[0x00] }))
    }

    /// Encodes a big-endian-encoded integer as an ASN.1 integer using DER.
    pub fn der_integer<'a, W: Write + 'a>(mut num: &'a [u8]) -> impl SerializeFn<W> + 'a {
        // DER: Leading zeroes must be trimmed.
        while !num.is_empty() && num[0] == 0 {
            num = &num[1..];
        }

        der_tlv(
            DerType::Integer,
            pair(
                // DER: Leading bit of an unsigned integer must have value 0.
                cond(num.is_empty() || num[0] >= 0x80, slice(&[0])),
                slice(num),
            ),
        )
    }

    /// Encodes a usize as an ASN.1 integer using DER.
    pub fn der_integer_usize<W: Write>(num: usize) -> impl SerializeFn<W> {
        move |w: WriteContext<W>| der_integer(&num.to_be_bytes())(w)
    }

    /// Encodes an ASN.1 bit string using DER.
    ///
    /// From X.690 section 8.6:
    /// ```text
    /// - The contents octets for the primitive encoding shall contain an initial octet
    ///   followed by zero, one or more subsequent octets.
    /// - The initial octet shall encode, as an unsigned binary integer with bit 1 as the
    ///   least significant bit, the number of unused bits in the final subsequent octet.
    /// ```
    pub fn der_bit_string<'a, W: Write + 'a>(bytes: &'a [u8]) -> impl SerializeFn<W> + 'a {
        der_tlv(DerType::BitString, pair(be_u8(0), slice(bytes)))
    }

    /// Encodes an ASN.1 octet string using DER.
    ///
    /// From X.690 section 8.7.2:
    /// ```text
    /// The primitive encoding contains zero, one or more contents octets equal in value
    /// to the octets in the data value, in the order they appear in the data value, and
    /// with the most significant bit of an octet of the data value aligned with the most
    /// significant bit of an octet of the contents octets.
    /// ```
    pub fn der_octet_string<'a, W: Write + 'a>(bytes: &'a [u8]) -> impl SerializeFn<W> + 'a {
        der_tlv(DerType::OctetString, slice(bytes))
    }

    /// Encodes an ASN.1 NULL using DER.
    ///
    /// From X.690 section 8.7.2:
    /// ```text
    /// The contents octets shall not contain any octets. Note – The length octet is zero.
    /// ```
    pub fn der_null<'a, W: Write + 'a>() -> impl SerializeFn<W> + 'a {
        der_tlv(DerType::Null, Ok)
    }

    /// Encodes an ASN.1 Object Identifier using DER.
    ///
    /// # Panics
    ///
    /// Panics if `oid.as_ref().len() < 2`.
    pub fn der_oid<W: Write, OID: Oid>(oid: OID) -> impl SerializeFn<W> {
        /// From X.690 section 8.19.2:
        /// ```text
        /// Each subidentifier is represented as a series of (one or more) octets. Bit 8
        /// of each octet indicates whether it is the last in the series: bit 8 of the
        /// last octet is zero; bit 8 of each preceding octet is one. Bits 7 to 1 of the
        /// octets in the series collectively encode the subidentifier. Conceptually,
        /// these groups of bits are concatenated to form an unsigned binary number whose
        /// most significant bit is bit 7 of the first octet and whose least significant
        /// bit is bit 1 of the last octet. The subidentifier shall be encoded in the
        /// fewest possible octets, that is, the leading octet of the subidentifier shall
        /// not have the value 0x80.
        /// ```
        fn subidentifier<W: Write>(id: u64) -> impl SerializeFn<W> {
            let id_bytes = [
                0x80 | ((id >> (9 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (8 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (7 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (6 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (5 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (4 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (3 * 7)) as u8 & 0x7f),
                0x80 | ((id >> (2 * 7)) as u8 & 0x7f),
                0x80 | ((id >> 7) as u8 & 0x7f),
                id as u8 & 0x7f,
            ];

            move |w: WriteContext<W>| {
                let mut id_slice = &id_bytes[..];
                while !id_slice.is_empty() && id_slice[0] == 0x80 {
                    id_slice = &id_slice[1..];
                }
                slice(id_slice)(w)
            }
        }

        move |w: WriteContext<W>| {
            let oid_slice = oid.as_ref();
            assert!(oid_slice.len() >= 2);

            der_tlv(
                DerType::Oid,
                pair(
                    // The numerical value of the first subidentifier is derived from the
                    // values of the first two object identifier components.
                    subidentifier(oid_slice[0] * 40 + oid_slice[1]),
                    all(oid_slice[2..].iter().map(|id| subidentifier(*id))),
                ),
            )(w)
        }
    }

    /// Encodes an ASN.1 UTF8String using DER.
    pub fn der_utf8_string<'a, W: Write + 'a>(s: &'a str) -> impl SerializeFn<W> + 'a {
        der_tlv(DerType::Utf8String, string(s))
    }

    /// Encodes the output of a sequence of serializers as an ASN.1 sequence using DER.
    pub fn der_sequence<W: Write, List: Tuple<Vec<u8>>>(l: List) -> impl SerializeFn<W> {
        der_tlv(DerType::Sequence, move |w: WriteContext<Vec<u8>>| {
            l.serialize(w)
        })
    }

    /// Encodes the output of a sequence of serializers as an ASN.1 set using DER.
    pub fn der_set<W: Write, List: Tuple<Vec<u8>>>(l: List) -> impl SerializeFn<W> {
        // DER: The encodings of the component values of a set value shall appear in an
        // order determined by their tags.
        // TODO: Try to enforce this here.
        der_tlv(DerType::Set, move |w: WriteContext<Vec<u8>>| l.serialize(w))
    }

    /// Encodes an ASN.1 UTCTime using DER.
    pub fn der_utc_time<W: Write>(t: DateTime<Utc>) -> impl SerializeFn<W> {
        der_tlv(
            DerType::UtcTime,
            string(t.format("%y%m%d%H%M%SZ").to_string()),
        )
    }

    /// Encodes an ASN.1 GeneralizedTime using DER.
    pub fn der_generalized_time<W: Write>(t: DateTime<Utc>) -> impl SerializeFn<W> {
        der_tlv(
            DerType::GeneralizedTime,
            string(t.format("%Y%m%d%H%M%SZ").to_string()),
        )
    }

    #[cfg(test)]
    mod tests {
        use cookie_factory::gen_simple;

        use super::*;

        #[test]
        fn der_types() {
            // INTEGER
            assert_eq!(
                gen_simple(der_type(DerType::Integer), vec![]).unwrap(),
                &[0x02]
            );
            // SEQUENCE
            assert_eq!(
                gen_simple(der_type(DerType::Sequence), vec![]).unwrap(),
                &[0x30]
            );
        }

        #[test]
        fn der_lengths() {
            assert_eq!(gen_simple(der_length(1), vec![]).unwrap(), &[1]);
            assert_eq!(gen_simple(der_length(127), vec![]).unwrap(), &[127]);
            assert_eq!(
                gen_simple(der_length(128), vec![]).unwrap(),
                &[0x80 | 1, 128]
            );
            assert_eq!(
                gen_simple(der_length(255), vec![]).unwrap(),
                &[0x80 | 1, 255]
            );
            assert_eq!(
                gen_simple(der_length(256), vec![]).unwrap(),
                &[0x80 | 2, 1, 0]
            );
        }

        #[test]
        fn der_tlvs() {
            assert_eq!(
                gen_simple(der_tlv(DerType::Integer, slice(&[0x07; 4])), vec![]).unwrap(),
                &[0x02, 0x04, 0x07, 0x07, 0x07, 0x07]
            );
        }

        #[test]
        fn der_usize_integers() {
            assert_eq!(
                gen_simple(der_integer_usize(0), vec![]).unwrap(),
                vec![2, 1, 0]
            );
            assert_eq!(
                gen_simple(der_integer_usize(127), vec![]).unwrap(),
                vec![2, 1, 127]
            );
            assert_eq!(
                gen_simple(der_integer_usize(128), vec![]).unwrap(),
                vec![2, 2, 0, 128]
            );
            assert_eq!(
                gen_simple(der_integer_usize(255), vec![]).unwrap(),
                vec![2, 2, 0, 255]
            );
            assert_eq!(
                gen_simple(der_integer_usize(256), vec![]).unwrap(),
                vec![2, 2, 1, 0]
            );
            assert_eq!(
                gen_simple(der_integer_usize(32767), vec![]).unwrap(),
                vec![2, 2, 127, 255]
            );
            assert_eq!(
                gen_simple(der_integer_usize(32768), vec![]).unwrap(),
                vec![2, 3, 0, 128, 0]
            );
            assert_eq!(
                gen_simple(der_integer_usize(65535), vec![]).unwrap(),
                vec![2, 3, 0, 255, 255]
            );
            assert_eq!(
                gen_simple(der_integer_usize(65536), vec![]).unwrap(),
                vec![2, 3, 1, 0, 0]
            );
        }
    }
}
