using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace CertCreator.UnitTest
{
    public abstract class TestCertBase
    {
        protected static readonly X509ChainStatusFlags[] ValidFlags =
        {
            X509ChainStatusFlags.NoError,
            X509ChainStatusFlags.Revoked,
            X509ChainStatusFlags.NotSignatureValid,
            X509ChainStatusFlags.UntrustedRoot,
            X509ChainStatusFlags.RevocationStatusUnknown,
            X509ChainStatusFlags.PartialChain,
            X509ChainStatusFlags.CtlNotSignatureValid,
            X509ChainStatusFlags.OfflineRevocation,
            //X509ChainStatusFlags.HasWeakSignature,
        };

        protected bool ValidateCertificate(X509Certificate2 cert)
        {
            var chain = new X509Chain
            {
                ChainPolicy =
                {
                    VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown |
                                        X509VerificationFlags.IgnoreCtlSignerRevocationUnknown |
                                        X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                        X509VerificationFlags.IgnoreRootRevocationUnknown
                }
            };

            chain.Build(cert);

            if (chain.ChainElements.Count == 0)
            {
                return false;
            }

            foreach (var chStatus in chain.ChainStatus)
            {
                if (!ValidFlags.Contains(chStatus.Status))
                {
                    return false;
                }
            }

            return true;
        }

    }
}
