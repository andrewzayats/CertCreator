namespace CertCreator.Cryptography
{
    public interface ISignatureConfig
    {
        int RsaKeyStrength { get; }

        int DsaKeySize { get; }

        int DsaKeyCertainty { get; }

        string CurveName { get; }
    }
}
