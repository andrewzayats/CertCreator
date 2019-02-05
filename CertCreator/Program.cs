using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CertCreator.CommandLineParsing;
using CertCreator.Cryptography;
using CommandLine;
using Org.BouncyCastle.Asn1.X509;

namespace CertCreator
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            var parseRes = Parser.Default.ParseArguments<SelfSignedCertArgs, CaCertArgs, IssuedCertArgs, BatchIssuedCertArgs, ScomCertArgs>(args);

            var execRes = parseRes.MapResult(
                (SelfSignedCertArgs info) => CreateSelfSignedCert(info),
                (CaCertArgs info) => CreateCaCert(info),
                (IssuedCertArgs info) => CreateIssuedCert(info),
                (BatchIssuedCertArgs info) => CreateBatchIssuedCerts(info),
                (ScomCertArgs info) => CreateScomCert(info),
                errs => -1
                );
            
            return execRes;
        }

        #region Actions

        private static int CreateSelfSignedCert(SelfSignedCertArgs certArgs)
        {
            return ErrorWrapper(
                    () =>
                        SingleCertActionWrapper(
                            () => InitCertBuilder(certArgs.SubjectName, certArgs.ValidityYears, CertificateBuilderFactory.CertBuilderType.SelfSigned).Build(),
                            certArgs.SubjectOutputPath, certArgs.SubjectPassword));
        }

        private static int CreateCaCert(CaCertArgs certArgs)
        {
            return ErrorWrapper(
                    () =>
                        SingleCertActionWrapper(
                            () => InitCertBuilder(certArgs.SubjectName, certArgs.ValidityYears, CertificateBuilderFactory.CertBuilderType.CA).Build(),
                            certArgs.SubjectOutputPath, certArgs.SubjectPassword));
        }

        private static int CreateIssuedCert(IssuedCertArgs certArgs)
        {
            return ErrorWrapper(
                    () =>
                        SingleCertActionWrapper(
                            () =>
                            {
                                var issuerCertificate = CertUtility.LoadCertificate(certArgs.IssuerFilePath, certArgs.IssuerPassword);

                                var builder = InitCertBuilder(certArgs.SubjectName, certArgs.ValidityYears, CertificateBuilderFactory.CertBuilderType.ClientServer);

                                builder.IssuerCertificate = issuerCertificate;
                                builder.SubjectAlternativeNames = certArgs.SanNames;

                                return builder.Build();
                            }, 
                            certArgs.SubjectOutputPath, certArgs.SubjectPassword));
        }

        private static int CreateBatchIssuedCerts(BatchIssuedCertArgs certArgs)
        {
            return ErrorWrapper(() =>
            {
                var issuerCertificate = CertUtility.LoadCertificate(certArgs.IssuerFilePath, certArgs.IssuerPassword);
                var path = Path.Combine(certArgs.OutputDir, certArgs.NamePrefix);
                var leadingZeros = certArgs.LeadingZeros > 0 ? certArgs.LeadingZeros : 0;
                var numStrFormat = "D" + leadingZeros;

                var builder = InitCertBuilder("init", certArgs.ValidityYears, CertificateBuilderFactory.CertBuilderType.Empty);
                builder.IssuerCertificate = issuerCertificate;
                builder.Usages = new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth };

                for (var i = certArgs.RangeBegin; i <= certArgs.RangeEnd; i++)
                {
                    Console.WriteLine($"Processing {i}");
                    var name = CertUtility.CheckAndCorrectName($"{certArgs.NamePrefix}{i.ToString(numStrFormat)}");
                    builder.SubjectName = name;
                    var cert = builder.Build();
                    var filePath = $"{path}{i.ToString(numStrFormat)}.pfx";
                    CertUtility.WriteCertificate(cert, filePath, certArgs.SubjectPassword);
                }
                Console.WriteLine("Success!");
            });
        }

        private static int CreateScomCert(ScomCertArgs certArgs)
        {
            return ErrorWrapper(
                () =>
                    SingleCertActionWrapper(
                        () =>
                        {
                            var issuerCertificate = CertUtility.LoadCertificate(certArgs.IssuerFilePath, certArgs.IssuerPassword);

                            var builder = InitCertBuilder(certArgs.SubjectName, certArgs.ValidityYears, CertificateBuilderFactory.CertBuilderType.Scom);

                            builder.IssuerCertificate = issuerCertificate;

                            return builder.Build();
                        },
                        certArgs.SubjectOutputPath, certArgs.SubjectPassword));
        }

        #endregion

        #region Helpers

        private static void SingleCertActionWrapper(Func<X509Certificate2> certAction, string outputPath, string password)
        {
            var cert = certAction();
            CertUtility.WriteCertificate(cert, outputPath, password);
            Console.WriteLine("Success!");
        }

        private static int ErrorWrapper(Action action)
        {
            try
            {
                if (!AlgorithmTypeHelper.GetSupportedSignatureAlgorithms()
                        .Contains(GlobalConfig.Instance.SignatureAlgorithm.ToUpperInvariant()))
                {
                    throw new Exception("Signature algorithm is not supported");
                }

                action();
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: {0}", ex.Message);
                return -1;
            }
            return 0;
        }

        private static int CheckValidityPeriod(int? validityYears)
        {
            if (!validityYears.HasValue)
            {
                return 2;
            }

            return validityYears.Value < 2 ? 2 : validityYears.Value;
        }

        private static CertificateBuilder InitCertBuilder(string subjName, int? validityYears, CertificateBuilderFactory.CertBuilderType builderType)
        {
            var name = CertUtility.CheckAndCorrectName(subjName);
            var years = CheckValidityPeriod(validityYears);
            var builder = CertificateBuilderFactory.Instance.GetBuilder(builderType);

            builder.SubjectName = name;
            builder.NotAfter = DateTime.UtcNow.AddYears(years);

            return builder;
        }

        #endregion
    }
}