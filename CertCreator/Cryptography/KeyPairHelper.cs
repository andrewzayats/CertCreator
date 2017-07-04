using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace CertCreator.Cryptography
{
    public class KeyPairHelper
    {
        #region Fields

        private readonly ISignatureConfig _config;

        #endregion

        public KeyPairHelper(ISignatureConfig config)
        {
            _config = config;
        }

        #region Public Methods

        public static IAsymmetricCipherKeyPairGenerator GetRsaKeyPairGenerator(SecureRandom random, int strength)
        {
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            return keyPairGenerator;
        }

        public static IAsymmetricCipherKeyPairGenerator GetDsaKeyPairGenerator(SecureRandom random, int size, int certainty)
        {
            var pGen = new DsaParametersGenerator();
            pGen.Init(size, certainty, random);

            var parameters = pGen.GenerateParameters();
            var genParam = new DsaKeyGenerationParameters(random, parameters);

            var dsaKeyGen = new DsaKeyPairGenerator();
            dsaKeyGen.Init(genParam);

            return dsaKeyGen;
        }

        public static IAsymmetricCipherKeyPairGenerator GetECDsaKeyPairGenerator(SecureRandom random, string curveName)
        {
            return GetECKeyPairGeneratorCommon(random, curveName, "ECDSA");
        }

        public static IAsymmetricCipherKeyPairGenerator GetECGost3410KeyPairGenerator(SecureRandom random, string curveName)
        {
            return GetECKeyPairGeneratorCommon(random, curveName, "ECGOST3410");
        }

        public static IAsymmetricCipherKeyPairGenerator GetGost3410x94KeyPairGenerator(SecureRandom random)
        {
            var parameters = new Gost3410KeyGenerationParameters(new SecureRandom(), CryptoProObjectIdentifiers.GostR3410x94CryptoProA);
            var keyGen = new Gost3410KeyPairGenerator();
            keyGen.Init(parameters);

            return keyGen;
        }

        public IAsymmetricCipherKeyPairGenerator GetKeyPairGenerator(string signatureAlgorithm, SecureRandom random)
        {
            var cipherAlgType = AlgorithmTypeHelper.GetCryptoAlgorithm(signatureAlgorithm);

            switch (cipherAlgType)
            {
                case AlgorithmTypeHelper.CipherAlgorithm.Rsa:
                    return GetRsaKeyPairGenerator(random, _config.RsaKeyStrength);
                case AlgorithmTypeHelper.CipherAlgorithm.Dsa:
                    return GetDsaKeyPairGenerator(random, _config.DsaKeySize, _config.DsaKeyCertainty);
                case AlgorithmTypeHelper.CipherAlgorithm.Gost3410x94:
                    return GetGost3410x94KeyPairGenerator(random);
                case AlgorithmTypeHelper.CipherAlgorithm.ECDsa:
                    return GetECDsaKeyPairGenerator(random, _config.CurveName);
                //case KeyPairHelper.CipherAlgorithm.Gost3410x2001:
                //    return GetECGost3410KeyPairGenerator(random, _config.CurveName);
                default:
                    throw new Exception("Unsupported signature algorithm");
            }
        }

        public static AsymmetricCipherKeyPair GetKeyPair(X509Certificate2 cert)
        {
            var pkcs12Bytes = cert.Export(X509ContentType.Pkcs12, "1");
            var pkcs12 = new Pkcs12StoreBuilder().Build();
            using (var ms = new MemoryStream(pkcs12Bytes, false))
            {
                pkcs12.Load(ms, new[] { '1' });
            }

            AsymmetricKeyParameter privateKey = null;
            foreach (string alias in pkcs12.Aliases)
            {
                if (pkcs12.IsKeyEntry(alias))
                {
                    privateKey = pkcs12.GetKey(alias).Key;
                    break;
                }
            }
            var bcCert = DotNetUtilities.FromX509Certificate(cert);
            var publicKey = bcCert.GetPublicKey();

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        #endregion

        #region Non-Public Methods

        protected static DerObjectIdentifier GetCurveOid(string curveName)
        {
            DerObjectIdentifier oid = null;

            oid = NistNamedCurves.GetOid(curveName);
            if (oid != null)
            {
                return oid;
            }

            oid = X962NamedCurves.GetOid(curveName);
            if (oid != null)
            {
                return oid;
            }

            oid = TeleTrusTNamedCurves.GetOid(curveName);
            if (oid != null)
            {
                return oid;
            }

            //sect* - currently are not supported
            oid = SecNamedCurves.GetOid(curveName);
            if (oid != null)
            {
                return oid;
            }

            //Are not supported
            //id = AnssiNamedCurves.GetOid(curveName);
            //if (id != null)
            //{
            //    return id;
            //}          

            throw new Exception("Unsupported curve type");
        }

        protected static X9ECParameters GetECParameters(string curveName)
        {
            X9ECParameters ecParams = null;

            ecParams = AnssiNamedCurves.GetByName(curveName);
            if (ecParams != null)
            {
                return ecParams;
            }

            ecParams = TeleTrusTNamedCurves.GetByName(curveName);
            if (ecParams != null)
            {
                return ecParams;
            }

            ecParams = NistNamedCurves.GetByName(curveName);
            if (ecParams != null)
            {
                return ecParams;
            }


            ecParams = SecNamedCurves.GetByName(curveName);
            if (ecParams != null)
            {
                return ecParams;
            }

            ecParams = X962NamedCurves.GetByName(curveName);
            if (ecParams != null)
            {
                return ecParams;
            }

            ecParams = CustomNamedCurves.GetByName(curveName);
            if (ecParams != null)
            {
                return ecParams;
            }

            throw new Exception("Unsupported curve type");
        }

        protected static IAsymmetricCipherKeyPairGenerator GetECKeyPairGeneratorCommon(SecureRandom random, string curveName, string algorithm)
        {
            var oid = GetCurveOid(curveName);
            var pGen = new ECKeyPairGenerator(algorithm);
            var genParam = new ECKeyGenerationParameters(oid, random);
            pGen.Init(genParam);

            return pGen;
        }

        #endregion
    }
}
