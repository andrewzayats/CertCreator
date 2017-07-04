using CertCreator.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1.X509;

namespace CertCreator.UnitTest
{
    [TestClass]
    public class TestSelfSignedCert: TestCertBase
    {
        [TestMethod]
        public void SS_SimpleTest()
        {
            var config = GlobalConfig.Instance;

            SimpleTestInternal(config, "SHA512WITHRSA");
            SimpleTestInternal(config, "SHA256WITHECDSA");
            SimpleTestInternal(config, "SHA1WITHDSA");
            //SimpleTestInternal(config, "RIPEMD256WITHRSA");
        }

        private void SimpleTestInternal(ISignatureConfig config, string signatureAlgorithm)
        {
            var factory = new CertificateBuilderFactory(config, signatureAlgorithm);

            var ssName = $"CN=ss_{signatureAlgorithm}";

            var builder = factory.GetBuilder(CertificateBuilderFactory.CertBuilderType.SelfSigned);
            builder.SubjectName = ssName;
            builder.Usages = new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth };
            var ssCert = builder.Build();

            Assert.IsTrue(ValidateCertificate(ssCert));
            Assert.AreEqual(ssCert.Subject, ssName);
            Assert.AreEqual(ssCert.Subject, ssCert.Issuer);
        }
    }
}
