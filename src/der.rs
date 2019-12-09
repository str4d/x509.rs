/// DER types that we care about.
enum DerType {
    Integer,
    Sequence,
}

impl DerType {
    /// Returns the class, encoding, and type number for this type.
    pub(super) fn parts(&self) -> (u8, u8, u8) {
        match self {
            // Universal | Primitive | INTEGER
            DerType::Integer => (0, 0, 2),
            // Universal | Constructed | SEQUENCE
            DerType::Sequence => (0, 1, 16),
        }
    }
}

pub mod write {
    use cookie_factory::{
        bytes::be_u8,
        combinator::{cond, slice},
        gen_simple,
        sequence::{pair, tuple, Tuple},
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::DerType;

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

    /// Encodes the output of a sequence of serializers as an ASN.1 sequence using DER.
    pub fn der_sequence<W: Write, List: Tuple<Vec<u8>>>(l: List) -> impl SerializeFn<W> {
        der_tlv(DerType::Sequence, move |w: WriteContext<Vec<u8>>| {
            l.serialize(w)
        })
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
