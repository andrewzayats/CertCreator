using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CertCreator.Cryptography
{
    public class CertificateBuilder
    {
        #region Fields

        private X509Certificate2 _issuerCertificate;

        private string _subjectName;

        #endregion

        #region Properties

        public string SubjectName { get; set; }

        public IEnumerable<string> SubjectAlternativeNames { get; set; }

        public KeyUsage KeyUsage { get; set; }

        public IEnumerable<KeyPurposeID> Usages { get; set; }

        public string SignatureAlgorithm { get; set; }

        public DateTime? NotBefore { get; set; }

        public DateTime? NotAfter { get; set; }

        public string IssuerName => _issuerCertificate?.Issuer;
       
        public bool IsCertificateAuthority { get; set; }

        public X509Certificate2 IssuerCertificate
        {
            private get { return _issuerCertificate; }
            set
            {
                if (value.HasPrivateKey)
                {
                    _issuerCertificate = value;
                }
            }
        }

        public bool IsSelfSigned { get; set; }

        public ISignatureConfig SignatureConfig { get; set; }

        public CertificatePolicies CertificatePolicies { get; set; }

        public Dictionary<DerObjectIdentifier, IEnumerable<PolicyQualifierInfo>> CertificatePoliciesDict
        {
            set => CertificatePolicies = CertUtility.GetCertPolicies(value);
        }

        #endregion

        #region Methods

        protected virtual IAsymmetricCipherKeyPairGenerator GetKeyPairGenerator(SecureRandom random)
        {
            if (SignatureConfig == null)
            {
                throw new Exception("SignatureConfig is not set");
            }
            var helper = new KeyPairHelper(SignatureConfig);
            return helper.GetKeyPairGenerator(SignatureAlgorithm, random);
        }

        protected virtual SecureRandom GetSecureRandom()
        {
            return CertUtility.GetSecureRandom();
        }

        public X509Certificate2 Build()
        {
            if (string.IsNullOrEmpty(SubjectName))
            {
                throw new Exception("Subject name is not set");
            }

            if (string.IsNullOrEmpty(SignatureAlgorithm))
            {
                throw new Exception("SignatureAlgorithm is not set");
            }

            if (!IsSelfSigned && _issuerCertificate == null)
            {
                throw new Exception("Issuer's certificate is not set");
            }

            var random = GetSecureRandom();

            var generator = GetKeyPairGenerator(random);
            var subjectKeyPair = generator.GenerateKeyPair();

            var subjectSerialNumber = CertUtility.GenerateSerialNumber(random);

            var subjectName = SubjectName;
            
            var issuerName = subjectName;
            var issuerSerialNumber = subjectSerialNumber;
            var issuerKeyPair = subjectKeyPair;
            
            if (!IsSelfSigned)
            {
                issuerName = IssuerCertificate.Subject;
                issuerSerialNumber = new BigInteger(IssuerCertificate.GetSerialNumber());
                issuerKeyPair = KeyPairHelper.GetKeyPair(IssuerCertificate);
            }

            var certificateGenerator = new X509V3CertificateGenerator();
            
            certificateGenerator.SetSerialNumber(subjectSerialNumber);

            var subjectDN = new X509Name(subjectName);
            certificateGenerator.SetSubjectDN(subjectDN);

            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);

            // Our certificate needs valid from/to values.
            var notBefore = NotBefore ?? DateTime.UtcNow.Date;
            var notAfter = NotAfter ?? notBefore.AddYears(1);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            if (IsSelfSigned)
            {
                certificateGenerator.AddAuthorityKeyIdentifier(issuerDN, issuerKeyPair, issuerSerialNumber);
            }
            else
            {
                certificateGenerator.AddAuthorityKeyIdentifier(IssuerCertificate);
            }

            certificateGenerator.AddSubjectKeyIdentifier(subjectKeyPair);
            certificateGenerator.AddBasicConstraints(IsCertificateAuthority);

            if (KeyUsage != null)
            {
                certificateGenerator.AddKeyUsage(KeyUsage);
            }

            if (Usages != null && Usages.Any())
            {
                certificateGenerator.AddExtendedKeyUsage(Usages.ToArray());
            }

            if (SubjectAlternativeNames != null && SubjectAlternativeNames.Any())
            {
                certificateGenerator.AddSubjectAlternativeNames(SubjectAlternativeNames);
            }

            if (CertificatePolicies != null)
            {
                certificateGenerator.AddCertificatePolicies(CertificatePolicies);
            }

            var signatureFactory = new Asn1SignatureFactory(SignatureAlgorithm, issuerKeyPair.Private, random);
            var certificate = certificateGenerator.Generate(signatureFactory);

            return CertUtility.ConvertCertificate(certificate, subjectKeyPair, random);
        }

        #endregion
    }
}
