//! *Pure-Rust X.509 certificate serialization*
//!
//! `x509` is a crate providing serialization APIs for X.509 v3 ([RFC 5280]) certificates,
//! implemented using the `cookie-factory` combinatorial serializer framework.
//!
//! [RFC 5280]: https://tools.ietf.org/html/rfc5280

use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

pub mod der;

/// A trait for objects which represent ASN.1 `AlgorithmIdentifier`s.
pub trait AlgorithmIdentifier {
    type AlgorithmOid: der::Oid;

    /// Returns the object identifier for this `AlgorithmIdentifier`.
    fn algorithm(&self) -> Self::AlgorithmOid;

    /// Writes the parameters for this `AlgorithmIdentifier`, if any.
    fn parameters<W: Write>(&self, w: WriteContext<W>) -> GenResult<W>;
}

/// A trait for objects which represent ASN.1 `SubjectPublicKeyInfo`s.
pub trait SubjectPublicKeyInfo {
    type AlgorithmId: AlgorithmIdentifier;
    type SubjectPublicKey: AsRef<[u8]>;

    /// Returns the [`AlgorithmIdentifier`] for this public key.
    fn algorithm_id(&self) -> Self::AlgorithmId;

    /// Returns the encoded public key.
    fn public_key(&self) -> Self::SubjectPublicKey;
}

/// X.509 serialization APIs.
pub mod write {
    use chrono::{DateTime, Datelike, TimeZone, Utc};
    use cookie_factory::{
        combinator::{cond, slice},
        sequence::pair,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::{
        der::{write::*, Oid},
        AlgorithmIdentifier, SubjectPublicKeyInfo,
    };

    /// X.509 versions that we care about.
    #[derive(Clone, Copy)]
    enum Version {
        V3,
    }

    impl From<Version> for usize {
        fn from(version: Version) -> usize {
            match version {
                Version::V3 => 2,
            }
        }
    }

    /// Object identifiers used internally by X.509.
    enum InternalOid {
        IdAtCommonName,
    }

    impl AsRef<[u64]> for InternalOid {
        fn as_ref(&self) -> &[u64] {
            match self {
                InternalOid::IdAtCommonName => &[2, 5, 4, 3],
            }
        }
    }

    impl Oid for InternalOid {}

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// TBSCertificate  ::=  SEQUENCE  {
    ///      version         [0]  EXPLICIT Version DEFAULT v1,
    ///      ...
    ///      }
    ///
    /// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    /// ```
    fn version<W: Write>(version: Version) -> impl SerializeFn<W> {
        // TODO: Omit version if V1, once x509-parser correctly handles this.
        der_explicit(0, der_integer_usize(version.into()))
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1.1.2):
    /// ```text
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///      algorithm               OBJECT IDENTIFIER,
    ///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
    /// ```
    pub fn algorithm_identifier<'a, W: Write + 'a, Alg: AlgorithmIdentifier>(
        algorithm_id: &'a Alg,
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((
            der_oid(algorithm_id.algorithm()),
            move |w: WriteContext<Vec<u8>>| algorithm_id.parameters(w),
        ))
    }

    /// Encodes a `str` as an X.509 Common Name.
    ///
    /// From [RFC 5280 section 4.1.2.4](https://tools.ietf.org/html/rfc5280#section-4.1.2.4):
    /// ```text
    /// Name ::= CHOICE { -- only one possibility for now --
    ///   rdnSequence  RDNSequence }
    ///
    /// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    ///
    /// RelativeDistinguishedName ::=
    ///   SET SIZE (1..MAX) OF AttributeTypeAndValue
    ///
    /// AttributeTypeAndValue ::= SEQUENCE {
    ///   type     AttributeType,
    ///   value    AttributeValue }
    ///
    /// AttributeType ::= OBJECT IDENTIFIER
    ///
    /// AttributeValue ::= ANY -- DEFINED BY AttributeType
    /// ```
    ///
    /// From [RFC 5280 appendix A.1](https://tools.ietf.org/html/rfc5280#appendix-A.1):
    /// ```text
    /// X520CommonName ::= CHOICE {
    ///      teletexString     TeletexString   (SIZE (1..ub-common-name)),
    ///      printableString   PrintableString (SIZE (1..ub-common-name)),
    ///      universalString   UniversalString (SIZE (1..ub-common-name)),
    ///      utf8String        UTF8String      (SIZE (1..ub-common-name)),
    ///      bmpString         BMPString       (SIZE (1..ub-common-name)) }
    ///
    /// ub-common-name INTEGER ::= 64
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `name.len() > 64`.
    fn name<'a, W: Write + 'a>(name: &'a str) -> impl SerializeFn<W> + 'a {
        assert!(name.len() <= 64);

        der_sequence((der_set((der_sequence((
            der_oid(InternalOid::IdAtCommonName),
            der_utf8_string(name),
        )),)),))
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Time ::= CHOICE {
    ///      utcTime        UTCTime,
    ///      generalTime    GeneralizedTime }
    ///
    /// CAs conforming to this profile MUST always encode certificate
    /// validity dates through the year 2049 as UTCTime; certificate validity
    /// dates in 2050 or later MUST be encoded as GeneralizedTime.
    /// ```
    fn time<W: Write>(t: DateTime<Utc>) -> impl SerializeFn<W> {
        pair(
            cond(t.year() < 2050, der_utc_time(t)),
            cond(t.year() >= 2050, der_generalized_time(t)),
        )
    }

    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Validity ::= SEQUENCE {
    ///      notBefore      Time,
    ///      notAfter       Time }
    ///
    /// To indicate that a certificate has no well-defined expiration date,
    /// the notAfter SHOULD be assigned the GeneralizedTime value of
    /// 99991231235959Z.
    /// ```
    fn validity<W: Write>(
        not_before: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
    ) -> impl SerializeFn<W> {
        der_sequence((
            time(not_before),
            time(not_after.unwrap_or_else(|| Utc.ymd(9999, 12, 31).and_hms(23, 59, 59))),
        ))
    }

    /// Encodes a `PublicKeyInfo` as an ASN.1 `SubjectPublicKeyInfo` using DER.
    ///
    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///      algorithm            AlgorithmIdentifier,
    ///      subjectPublicKey     BIT STRING  }
    /// ```
    fn subject_public_key_info<'a, W: Write + 'a, PKI: SubjectPublicKeyInfo>(
        subject_pki: &'a PKI,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            der_sequence((
                algorithm_identifier(&subject_pki.algorithm_id()),
                der_bit_string(subject_pki.public_key().as_ref()),
            ))(w)
        }
    }

    /// Encodes a version 1 X.509 `TBSCertificate` using DER.
    ///
    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// TBSCertificate  ::=  SEQUENCE  {
    ///      version         [0]  EXPLICIT Version DEFAULT v1,
    ///      serialNumber         CertificateSerialNumber,
    ///      signature            AlgorithmIdentifier,
    ///      issuer               Name,
    ///      validity             Validity,
    ///      subject              Name,
    ///      subjectPublicKeyInfo SubjectPublicKeyInfo,
    ///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                           -- If present, version MUST be v2 or v3
    ///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                           -- If present, version MUST be v2 or v3
    ///      extensions      [3]  EXPLICIT Extensions OPTIONAL
    ///                           -- If present, version MUST be v3
    ///      }
    ///
    /// CertificateSerialNumber  ::=  INTEGER
    ///
    /// Certificate users MUST be able to handle serialNumber values up to 20 octets.
    /// Conforming CAs MUST NOT use serialNumber values longer than 20 octets.
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `serial_number.len() > 20`
    /// - `issuer.len() > 64`
    /// - `subject.len() > 64`
    pub fn tbs_certificate<'a, W: Write + 'a, Alg, PKI>(
        serial_number: &'a [u8],
        signature: &'a Alg,
        issuer: &'a str,
        not_before: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
        subject: &'a str,
        subject_pki: &'a PKI,
    ) -> impl SerializeFn<W> + 'a
    where
        Alg: AlgorithmIdentifier,
        PKI: SubjectPublicKeyInfo,
    {
        assert!(serial_number.len() <= 20);

        der_sequence((
            version(Version::V3),
            der_integer(serial_number),
            algorithm_identifier(signature),
            name(issuer),
            validity(not_before, not_after),
            name(subject),
            subject_public_key_info(subject_pki),
        ))
    }

    /// Encodes an X.509 certificate using DER.
    ///
    /// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
    /// ```text
    /// Certificate  ::=  SEQUENCE  {
    ///      tbsCertificate       TBSCertificate,
    ///      signatureAlgorithm   AlgorithmIdentifier,
    ///      signatureValue       BIT STRING  }
    /// ```
    ///
    /// Use [`tbs_certificate`] to serialize the certificate itself, then sign it and call
    /// this function with the serialized `TBSCertificate` and signature.
    pub fn certificate<'a, W: Write + 'a, Alg: AlgorithmIdentifier>(
        cert: &'a [u8],
        signature_algorithm: &'a Alg,
        signature: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        der_sequence((
            slice(cert),
            algorithm_identifier(signature_algorithm),
            der_bit_string(signature),
        ))
    }
}
