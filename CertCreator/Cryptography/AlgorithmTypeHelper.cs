using System;
using System.Collections.Generic;
using System.Linq;

namespace CertCreator.Cryptography
{
    internal static class AlgorithmTypeHelper
    {
        #region Types

        public class AlgorithmPair
        {
            public AlgorithmPair(CipherAlgorithm cipherAlgorithm, HashAlgorithm hashAlgorithm)
            {
                CipherAlgorithm = cipherAlgorithm;
                HashAlgorithm = hashAlgorithm;
            }

            public CipherAlgorithm CipherAlgorithm { get; set; }

            public HashAlgorithm HashAlgorithm { get; set; }
        }

        [Flags]
        internal enum CipherAlgorithm
        {
            Rsa,
            Dsa,
            ECDsa,
            Gost3410x94,
            Gost3410x2001
        }

        internal enum HashAlgorithm
        {
            MD2,
            MD5,
            Sha1,
            Sha224,
            Sha256,
            Sha384,
            Sha512,
            Gost3411,
            RIPEMD128,
            RIPEMD160,
            RIPEMD256
        }

        #endregion

        #region Fields

        public static readonly Dictionary<string, AlgorithmPair> AlgorithmMappings = new Dictionary
            <string, AlgorithmPair>
            {
                {"MD2WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.MD2)},
                {"MD2WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.MD2)},
                {"MD5WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.MD5)},
                {"MD5WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.MD5)},
                {"SHA1WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha1)},
                {"SHA1WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha1)},
                {"SHA224WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha224)},
                {"SHA224WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha224)},
                {"SHA256WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha256)},
                {"SHA256WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha256)},
                {"SHA384WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha384)},
                {"SHA384WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha384)},
                {"SHA512WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha512)},
                {"SHA512WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha512)},
                {"SHA1WITHRSAANDMGF1", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha1)},
                {"SHA224WITHRSAANDMGF1", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha224)},
                {"SHA256WITHRSAANDMGF1", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha256)},
                {"SHA384WITHRSAANDMGF1", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha384)},
                {"SHA512WITHRSAANDMGF1", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.Sha512)},
                {"RIPEMD160WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.RIPEMD160)},
                {"RIPEMD160WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.RIPEMD160)},
                {"RIPEMD128WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.RIPEMD128)},
                {"RIPEMD128WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.RIPEMD128)},
                {"RIPEMD256WITHRSAENCRYPTION", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.RIPEMD256)},
                {"RIPEMD256WITHRSA", new AlgorithmPair(CipherAlgorithm.Rsa, HashAlgorithm.RIPEMD256)},
                {"SHA1WITHDSA", new AlgorithmPair(CipherAlgorithm.Dsa, HashAlgorithm.Sha1)},
                {"DSAWITHSHA1", new AlgorithmPair(CipherAlgorithm.Dsa, HashAlgorithm.Sha1)},
                {"SHA224WITHDSA", new AlgorithmPair(CipherAlgorithm.Dsa, HashAlgorithm.Sha224)},
                {"SHA256WITHDSA", new AlgorithmPair(CipherAlgorithm.Dsa, HashAlgorithm.Sha256)},
                {"SHA384WITHDSA", new AlgorithmPair(CipherAlgorithm.Dsa, HashAlgorithm.Sha384)},
                {"SHA512WITHDSA", new AlgorithmPair(CipherAlgorithm.Dsa, HashAlgorithm.Sha512)},
                {"SHA1WITHECDSA", new AlgorithmPair(CipherAlgorithm.ECDsa, HashAlgorithm.Sha1)},
                {"ECDSAWITHSHA1", new AlgorithmPair(CipherAlgorithm.ECDsa, HashAlgorithm.Sha1)},
                {"SHA224WITHECDSA", new AlgorithmPair(CipherAlgorithm.ECDsa, HashAlgorithm.Sha224)},
                {"SHA256WITHECDSA", new AlgorithmPair(CipherAlgorithm.ECDsa, HashAlgorithm.Sha256)},
                {"SHA384WITHECDSA", new AlgorithmPair(CipherAlgorithm.ECDsa, HashAlgorithm.Sha384)},
                {"SHA512WITHECDSA", new AlgorithmPair(CipherAlgorithm.ECDsa, HashAlgorithm.Sha512)},
                {"GOST3411WITHGOST3410", new AlgorithmPair(CipherAlgorithm.Gost3410x94, HashAlgorithm.Gost3411)},
                {"GOST3411WITHGOST3410-94", new AlgorithmPair(CipherAlgorithm.Gost3410x94, HashAlgorithm.Gost3411)},
                {"GOST3411WITHECGOST3410", new AlgorithmPair(CipherAlgorithm.Gost3410x2001, HashAlgorithm.Gost3411)},
                {"GOST3411WITHECGOST3410-2001", new AlgorithmPair(CipherAlgorithm.Gost3410x2001, HashAlgorithm.Gost3411)},
                {"GOST3411WITHGOST3410-2001", new AlgorithmPair(CipherAlgorithm.Gost3410x2001, HashAlgorithm.Gost3411)}
            };

        #endregion

        public static CipherAlgorithm GetCryptoAlgorithm(string signatureAlgorithmName)
        {
            return AlgorithmMappings[signatureAlgorithmName.ToUpperInvariant()].CipherAlgorithm;
        }

        public static HashAlgorithm GetHashAlgorithm(string signatureAlgorithmName)
        {
            return AlgorithmMappings[signatureAlgorithmName.ToUpperInvariant()].HashAlgorithm;
        }

        public static IEnumerable<string> GetSupportedSignatureAlgorithms()
        {
            var supportedTypes = CipherAlgorithm.Rsa | CipherAlgorithm.Dsa | CipherAlgorithm.ECDsa;; //| CipherAlgorithm.Gost3410x94;
            return AlgorithmMappings.Where(p => supportedTypes.HasFlag(p.Value.CipherAlgorithm)).Select(p => p.Key);
        }
    }
}