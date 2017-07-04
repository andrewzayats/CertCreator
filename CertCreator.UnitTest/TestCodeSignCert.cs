using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CertCreator.UnitTest
{
    [TestClass]
    public class TestCodeSignCert : TestCertBase
    {
        [TestMethod]
        public void CodeSign_SimpleTest()
        {
            var builderCa = CertificateBuilderFactory.Instance.GetBuilder(CertificateBuilderFactory.CertBuilderType.CA_CodeSign);
            builderCa.SubjectName = "CN=testCS_CA";
            var certCa = builderCa.Build();

            var builder = CertificateBuilderFactory.Instance.GetBuilder(CertificateBuilderFactory.CertBuilderType.CodeSign);
            builder.SubjectName = "CN=testCS";
            builder.IssuerCertificate = certCa;
            var cert = builder.Build();

            Assert.IsTrue(ValidateCertificate(cert));
        }
    }
}
