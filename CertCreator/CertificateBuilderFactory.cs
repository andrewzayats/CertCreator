using System;
using CertCreator.Cryptography;
using Org.BouncyCastle.Asn1.X509;

namespace CertCreator
{
    internal class CertificateBuilderFactory
    {
        #region Types

        public enum CertBuilderType
        {
            SelfSigned,
            CA,
            CA_CodeSign,
            CodeSign,
            ClientServer,
            Scom,
            Empty
        }

        #endregion

        #region Fields

        private static CertificateBuilderFactory _instance;

        #endregion

        public CertificateBuilderFactory(ISignatureConfig config, string signatureAlgorithm)
        {
            SignatureConfig = config;
            SignatureAlgorithm = signatureAlgorithm;
        }

        public CertificateBuilder GetBuilder(CertBuilderType type)
        {
            switch (type)
            {
                case CertBuilderType.SelfSigned:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig,
                        IsSelfSigned = true,
                        NotAfter = DateTime.UtcNow.AddYears(10)
                    };
                case CertBuilderType.CA:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig,
                        IsSelfSigned = true,
                        IsCertificateAuthority = true,
                        NotAfter = DateTime.UtcNow.AddYears(10)
                    };
                case CertBuilderType.CA_CodeSign:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig,
                        IsSelfSigned = true,
                        IsCertificateAuthority = true,
                        KeyUsage = new KeyUsage(KeyUsage.DigitalSignature + KeyUsage.KeyCertSign + KeyUsage.CrlSign),
                        NotAfter = DateTime.UtcNow.AddYears(10)
                    };
                case CertBuilderType.CodeSign:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig,
                        Usages = new[] { KeyPurposeID.IdKPCodeSigning },
                        NotAfter = DateTime.UtcNow.AddYears(10)
                    };
                case CertBuilderType.ClientServer:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig,
                        Usages = new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth },
                        NotAfter = DateTime.UtcNow.AddYears(10)
                    };
                case CertBuilderType.Scom:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig,
                        KeyUsage = new KeyUsage(KeyUsage.DigitalSignature + KeyUsage.KeyEncipherment + KeyUsage.DataEncipherment),
                        Usages = new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth },
                        NotAfter = DateTime.UtcNow.AddYears(10)
                    };
                default:
                    return new CertificateBuilder
                    {
                        SignatureAlgorithm = SignatureAlgorithm,
                        SignatureConfig = SignatureConfig
                    };
            }
        }

        #region Properties

        public string SignatureAlgorithm { get; set; }

        public ISignatureConfig SignatureConfig { get; set; }

        public static CertificateBuilderFactory Instance => _instance ?? (_instance = new CertificateBuilderFactory(GlobalConfig.Instance, GlobalConfig.Instance.SignatureAlgorithm));

        #endregion
    }
}
