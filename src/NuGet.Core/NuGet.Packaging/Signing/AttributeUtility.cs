// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
#if IS_DESKTOP
using System.Security.Cryptography.Pkcs;
#endif
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NuGet.Common;
using NuGet.Packaging.Signing.DerEncoding;

namespace NuGet.Packaging.Signing
{
    public static class AttributeUtility
    {
#if IS_DESKTOP

        /// <summary>
        /// Create a CommitmentTypeIndication attribute.
        /// https://tools.ietf.org/html/rfc5126.html#section-5.11.1
        /// </summary>
        public static CryptographicAttributeObject GetCommitmentTypeIndication(SignatureType type)
        {
            string valueOid = null;

            // SignatureType -> Oid
            switch (type)
            {
                case SignatureType.Author:
                    valueOid = Oids.CommitmentTypeIdentifierProofOfOrigin;
                    break;
                case SignatureType.Repository:
                    valueOid = Oids.CommitmentTypeIdentifierProofOfOrigin;
                    break;
                default:
                    throw new ArgumentException(nameof(type));
            }

            // DER encode the signature type Oid in a sequence.
            // CommitmentTypeQualifier ::= SEQUENCE {
            // commitmentTypeIdentifier CommitmentTypeIdentifier,
            // qualifier                  ANY DEFINED BY commitmentTypeIdentifier }
            var commitmentTypeData = DerEncoder.ConstructSequence(new List<byte[][]>() { DerEncoder.SegmentedEncodeOid(valueOid) });
            var data = new AsnEncodedData(Oids.CommitmentTypeIndication, commitmentTypeData);

            // Create an attribute
            return new CryptographicAttributeObject(
                oid: new Oid(Oids.CommitmentTypeIndication),
                values: new AsnEncodedDataCollection(data));
        }

        /// <summary>
        /// Oid -> SignatureType
        /// </summary>
        /// <remarks>Unknown Oids are ignored. Throws for empty values and invalid combinations.</remarks>
        public static SignatureType GetCommitmentTypeIndication(CryptographicAttributeObject attribute)
        {
            var values = new List<SignatureType>(1);

            if (StringComparer.Ordinal.Equals(attribute.Oid.Value, Oids.CommitmentTypeIndication))
            {
                foreach (var value in attribute.Values)
                {
                    values.Add(GetSignatureType(value.Oid.Value));
                }
            }

            // Zero values is invalid.
            if (values.Count < 1)
            {
                throw new SignatureException(Strings.CommitmentTypeIndicationAttributeInvalid);
            }

            // Remove unknown values, these could be future values.
            var knownValues = values.Where(e => e != SignatureType.Unknown).ToList();

            // Currently the value must be a single value of author or repository. If multiple
            // known values exist then either there is a duplicate or both author and repository
            // was listed in the attribute.
            if (knownValues.Count > 1)
            {
                throw new SignatureException(Strings.CommitmentTypeIndicationAttributeInvalid);
            }

            // Return the only recognized value.
            if (knownValues.Count == 1)
            {
                return knownValues[0];
            }

            // All values were unknown
            return SignatureType.Unknown;
        }

        /// <summary>
        /// Oid -> SignatureType
        /// </summary>
        public static SignatureType GetSignatureType(string oid)
        {
            switch (oid)
            {
                case Oids.CommitmentTypeIdentifierProofOfOrigin:
                    return SignatureType.Author;
                case Oids.CommitmentTypeIdentifierProofOfReceipt:
                    return SignatureType.Repository;
                default:
                    return SignatureType.Unknown;
            }
        }

        /// <summary>
        /// SignatureType -> Oid
        /// </summary>
        public static string GetSignatureTypeOid(SignatureType signatureType)
        {
            switch (signatureType)
            {
                case SignatureType.Author:
                    return Oids.CommitmentTypeIdentifierProofOfOrigin;
                case SignatureType.Repository:
                    return Oids.CommitmentTypeIdentifierProofOfReceipt;
                default:
                    throw new ArgumentException(nameof(signatureType));
            }
        }

        /// <summary>
        /// signing-certificate-v2
        /// </summary>
        public static CryptographicAttributeObject GetSigningCertificateV2(X509Certificate2 cert)
        {
            var hashAlgorithm = Common.HashAlgorithmName.SHA512;

            var hashAlgorithmOid = hashAlgorithm.ConvertToOidString();
            var hashValue = GetCertificateHash(cert, hashAlgorithm);
            var serialBytes = GetSerialNumberBytes(cert.SerialNumber);

            var issuerSerial = new List<byte[][]>()
            {
                // GeneralNames

                // CertificateSerialNumber
                DerEncoder.SegmentedEncodeUnsignedInteger(serialBytes)
            };

            var essCertIDv2 = new List<byte[][]>()
            {
                // AlgorithmIdentifier
                DerEncoder.SegmentedEncodeOid(hashAlgorithmOid),
                // Hash
                DerEncoder.SegmentedEncodeOctetString(hashValue),
                // IssuerSerial
                DerEncoder.ConstructSegmentedSequence(issuerSerial)
            };

            var data = new AsnEncodedData(Oids.SigningCertificateV2, DerEncoder.ConstructSequence(essCertIDv2));

            // Create an attribute
            return new CryptographicAttributeObject(
                oid: new Oid(Oids.SigningCertificateV2),
                values: new AsnEncodedDataCollection(data));
        }

        public static bool IsSameCertificate(X509Certificate2 cert, CryptographicAttributeObject certAttribute)
        {
            var essCertIDv2 = certAttribute.Values.ToList();

            if (essCertIDv2.Count > 1)
            {
                var hashAlgorithm = CryptoHashUtility.OidToHashAlgorithmName(essCertIDv2[0].Oid.Value);
                var hashValue = GetCertificateHash(cert, hashAlgorithm);
                var attributeHashValue = essCertIDv2[0].RawData;

                return hashValue.SequenceEqual(attributeHashValue);
            }

            return false;
        }

        private static List<AsnEncodedData> ToList(this AsnEncodedDataCollection collection)
        {
            var values = new List<AsnEncodedData>();

            foreach (var value in collection)
            {
                values.Add(value);
            }

            return values;
        }

        private static byte[] GetCertificateHash(X509Certificate2 cert, Common.HashAlgorithmName hashAlgorithm)
        {
            return hashAlgorithm.GetHashProvider().ComputeHash(cert.RawData);
        }

        /// <summary>
        /// Hex string -> big endian byte array
        /// </summary>
        public static byte[] GetSerialNumberBytes(string serialNumber)
        {
            var count = serialNumber.Length;
            var bytes = new byte[count / 2];

            for (var i = 0; i < count; i += 2)
            {
                var pos = i / 2;
                var value = Convert.ToByte(serialNumber.Substring(i, 2), 16);
                bytes[pos] = value;
            }

            return bytes;
        }
#endif
    }
}
