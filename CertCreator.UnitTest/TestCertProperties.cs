using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace CertCreator.UnitTest
{
    [TestClass]
    public class TestCertProperties
    {
        private static readonly string SanExtOidStr = "2.5.29.17";
        private static readonly string EkuExtOidStr = "2.5.29.37";

        [TestMethod]
        public void TestExtension_SAN()
        {
            var sanNames = new[] {"name1", "name2", "name3"};

            var factory = new CertificateBuilderFactory(GlobalConfig.Instance, GlobalConfig.Instance.SignatureAlgorithm);

            var builder = factory.GetBuilder(CertificateBuilderFactory.CertBuilderType.SelfSigned);

            builder.SubjectName = "CN=san_test1";
            builder.SubjectAlternativeNames = sanNames;
            var cert = builder.Build();

            var ext = cert.Extensions[SanExtOidStr];
            var extText = Encoding.UTF8.GetString(ext.RawData, 4, ext.RawData.Length - 4);

            var separator = Encoding.UTF8.GetString(new byte[]{ 130, 5});

            var extNames = extText.Split(new[] { separator }, StringSplitOptions.RemoveEmptyEntries);
            
            Assert.IsTrue(sanNames.Length == extNames.Length && !sanNames.Except(extNames).Any());

            builder.SubjectAlternativeNames = null;
            cert = builder.Build();

            ext = cert.Extensions[SanExtOidStr];

            Assert.IsTrue(ext == null);
        }

        [TestMethod]
        public void TestExtension_EKU()
        {
            var clientServerEku = new[] {KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth};
            var codeSigningEku = new[] {KeyPurposeID.IdKPCodeSigning};

            var factory = new CertificateBuilderFactory(GlobalConfig.Instance, GlobalConfig.Instance.SignatureAlgorithm);

            var builder = factory.GetBuilder(CertificateBuilderFactory.CertBuilderType.SelfSigned);

            builder.SubjectName = "CN=eku_test1";
            builder.Usages = clientServerEku;

            var cert = builder.Build();

            var ext = (X509EnhancedKeyUsageExtension)cert.Extensions[EkuExtOidStr];

            var extOids = ext.EnhancedKeyUsages.OfType<Oid>().Select(o => o.Value).ToArray();
            var initOids = clientServerEku.Select(o => o.Id).ToArray();

            Assert.IsTrue(initOids.Length == extOids.Length && !initOids.Except(extOids).Any());

            builder.Usages = codeSigningEku;

            cert = builder.Build();

            ext = (X509EnhancedKeyUsageExtension)cert.Extensions[EkuExtOidStr];

            extOids = ext.EnhancedKeyUsages.OfType<Oid>().Select(o => o.Value).ToArray();
            initOids = codeSigningEku.Select(o => o.Id).ToArray();

            Assert.IsTrue(initOids.Length == extOids.Length && !initOids.Except(extOids).Any());
        }

        [TestMethod]
        public void TestExtension_Policies()
        {
            var builder =
                CertificateBuilderFactory.Instance.GetBuilder(CertificateBuilderFactory.CertBuilderType.SelfSigned);

            builder.SubjectName = "CN=test01";

            //var userNotice = new UserNotice(new NoticeReference("test", new[] {1, 2, 3}), "test");

            var seq = new DerSequence(
                //new DerSequence(
                //    new DerSequence(new DerInteger(1)),
                //    new DisplayText("test2")
                //),
                new DisplayText("test1")
            );

            builder.CertificatePoliciesDict =
                new Dictionary<DerObjectIdentifier, IEnumerable<PolicyQualifierInfo>>
                {
                    {new DerObjectIdentifier("2.23.140.1.2.1"), null},
                    {
                        new DerObjectIdentifier("1.3.6.1.4.1.311.46.3"), new[]
                        {
                            new PolicyQualifierInfo("localhost"),
                            new PolicyQualifierInfo(PolicyQualifierID.IdQtUnotice, seq),
                        }
                    }
                };

            var cert = builder.Build();

            var bytes = cert.Export(X509ContentType.Cert);
            File.WriteAllBytes(@"d:\Work\20170709\cert.cer", bytes);
        }
    }
}
