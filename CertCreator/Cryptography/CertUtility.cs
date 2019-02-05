using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertCreator.Cryptography
{
    public class CertUtility
    {
        private static readonly Regex SimpleNameRegex = new Regex(@"^\s*[A-Za-z]{1,3}=",RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

        public static X509Certificate2 ConvertCertificate(X509Certificate certificate,
            AsymmetricCipherKeyPair subjectKeyPair,
            SecureRandom random)
        {
            // Now to convert the Bouncy Castle certificate to a .NET certificate.
            // See http://web.archive.org/web/20100504192226/http://www.fkollmann.de/v2/post/Creating-certificates-using-BouncyCastle.aspx
            // ...but, basically, we create a PKCS12 store (a .PFX file) in memory, and add the public and private key to that.
            var store = new Pkcs12Store();

            // What Bouncy Castle calls "alias" is the same as what Windows terms the "friendly name".
            string friendlyName = certificate.SubjectDN.ToString();

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            // Add the private key.
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] {certificateEntry});

            // Convert it to an X509Certificate2 object by saving/loading it from a MemoryStream.
            // It needs a password. Since we'll remove this later, it doesn't particularly matter what we use.
            const string password = "password";
            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);

            var convertedCertificate =
                new X509Certificate2(stream.ToArray(),
                    password,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            return convertedCertificate;
        }

        public static X509Certificate2 LoadCertificate(string issuerFileName, string password = null)
        {
            // We need to pass 'Exportable', otherwise we can't get the private key.
            var issuerCertificate = new X509Certificate2(issuerFileName, password, X509KeyStorageFlags.Exportable);
            return issuerCertificate;
        }

        public static void WriteCertificate(X509Certificate2 certificate, string outputFileName, string password = null)
        {
            // This password is the one attached to the PFX file. Use 'null' for no password.
            var bytes = certificate.Export(X509ContentType.Pfx, password);

            File.WriteAllBytes(outputFileName, bytes);
        }

        /// <summary>
        /// The certificate needs a serial number. This is used for revocation,
        /// and usually should be an incrementing index (which makes it easier to revoke a range of certificates).
        /// Since we don't have anywhere to store the incrementing index, we can just use a random number.
        /// </summary>
        /// <param name="random"></param>
        /// <returns></returns>
        public static BigInteger GenerateSerialNumber(SecureRandom random)
        {
            var serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            return serialNumber;
        }

        /// <summary>
        /// Generate a key pair.
        /// </summary>
        /// <param name="random">The random number generator.</param>
        /// <param name="strength">The key length in bits. For RSA, 2048 bits should be considered the minimum acceptable these days.</param>
        /// <returns></returns>
        public static AsymmetricCipherKeyPair GenerateRsaKeyPair(SecureRandom random, int strength)
        {
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            return subjectKeyPair;
        }

        public static SecureRandom GetSecureRandom()
        {
            // Since we're on Windows, we'll use the CryptoAPI one (on the assumption
            // that it might have access to better sources of entropy than the built-in
            // Bouncy Castle ones):
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            return random;
        }

        public static string CheckAndCorrectName(string name)
        {
            return !SimpleNameRegex.IsMatch(name) ? $"CN={name}" : name;
        }

        public static BigInteger GetBigInteger(string str)
        {
            if (str.ToUpperInvariant().StartsWith("0X"))
            {
                return new BigInteger(str.Substring(2), 16);
            }
            return new BigInteger(str);
        }

        public static CngKey ConvertPrivateKeyToCngKey(AsymmetricKeyParameter privateKey)
        {
            var bcKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            var pkcs8Blob = bcKeyInfo.GetDerEncoded();
            var importedKey = CngKey.Import(pkcs8Blob, CngKeyBlobFormat.Pkcs8PrivateBlob);
            return importedKey;
        }

        public static KeyPurposeID GetKeyPurposeID(string oid)
        {
            var ci = typeof(KeyPurposeID).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).First();
            var obj = ci.Invoke(new object[] { oid });
            return obj as KeyPurposeID;
        }

        public static CertificatePolicies GetCertPolicies(Dictionary<DerObjectIdentifier, IEnumerable<PolicyQualifierInfo>> policiesDict)
        {
            var policies = new List<PolicyInformation>();
            foreach (var pair in policiesDict)
            {
                PolicyInformation info;

                if (pair.Value == null || !pair.Value.Any())
                {
                    info = new PolicyInformation(pair.Key);
                }
                else
                {                   
                    var qualifiers = new Asn1EncodableVector();
                    foreach (var qualifier in pair.Value)
                    {
                        qualifiers.Add(qualifier);
                    }

                    info = new PolicyInformation(pair.Key, new DerSequence(qualifiers));
                }
                policies.Add(info); 
            }

            return new CertificatePolicies(policies.ToArray());
        }


    }
}
