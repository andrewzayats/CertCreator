using CertCreator.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CertCreator.UnitTest
{
    [TestClass]
    public class TestCaCert: TestCertBase
    {
        [TestMethod]
        public void CA_SimpleTest()
        {
            var config = CertCreator.GlobalConfig.Instance;

            SimpleTestInternal(config, "SHA512WITHRSA");
            SimpleTestInternal(config, "SHA256WITHECDSA");
            SimpleTestInternal(config, "SHA1WITHDSA");
            //SimpleTestInternal(config, "RIPEMD256WITHRSA");
        }

        private void SimpleTestInternal(ISignatureConfig config, string signatureAlgorithm)
        {
            var factory = new CertificateBuilderFactory(config, signatureAlgorithm);

            var caName = $"CN=ca_{signatureAlgorithm}";

            var builder = factory.GetBuilder(CertCreator.CertificateBuilderFactory.CertBuilderType.CA);
            builder.SubjectName = caName;
            var caCert = builder.Build();

            Assert.IsTrue(ValidateCertificate(caCert));
            Assert.AreEqual<string>(caCert.Subject, caName);
            Assert.AreEqual<string>(caCert.Subject, caCert.Issuer);
        }

        [TestMethod]
        public void CA_SimpleChainTest()
        {
            var config = CertCreator.GlobalConfig.Instance;

            SimpleChainTestInternal(config, "SHA512WITHRSA");
            SimpleChainTestInternal(config, "SHA256WITHECDSA");
            //SimpleChainTestInternal(config, "SHA256WITHDSA");
            //SimpleChainTestInternal(config, "RIPEMD256WITHRSA");
        }

        private void SimpleChainTestInternal(ISignatureConfig config, string signatureAlgorithm)
        {
            var factory = new CertificateBuilderFactory(config, signatureAlgorithm);

            var caName = $"CN=ca_{signatureAlgorithm}";
            var isName = $"CN=is_{signatureAlgorithm}";

            var builder = factory.GetBuilder(CertCreator.CertificateBuilderFactory.CertBuilderType.CA);
            builder.SubjectName = caName;
            var caCert = builder.Build();

            //CertUtility.WriteCertificate(caCert, $"{signatureAlgorithm}_ca.pfx");

            var isBuilder = factory.GetBuilder(CertCreator.CertificateBuilderFactory.CertBuilderType.Empty);
            isBuilder.SubjectName = isName;
            isBuilder.IssuerCertificate = caCert;
            var isCert = isBuilder.Build();

            //CertUtility.WriteCertificate(caCert, $"{signatureAlgorithm}_is.pfx");

            Assert.IsTrue(ValidateCertificate(isCert));
            Assert.AreEqual<string>(isCert.Subject, isName);
            Assert.AreEqual<string>(isCert.Issuer, caCert.Subject);
        }
    }
}
