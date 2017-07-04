using System.Configuration;
using System.Data.SqlClient;
using CertCreator.Cryptography;

namespace CertCreator
{
    internal class GlobalConfig: ISignatureConfig
    {
        #region Fields

        private static GlobalConfig _instance;

        private const string DEFAULT_SIGNATURE_ALGORITHM = "SHA256WITHRSA";

        private const int MINIMAL_RSA_KEY_STRENGTH = 2048;

        private const int MINIMAL_DSA_KEY_SIZE = 512;

        private const int MINIMAL_DSA_KEY_CERTAINTY = 80;

        private const string DEFAULT_CURVE_NAME = "P-521";

        public static readonly bool RuntimeIs462OrHigher;

        #endregion

        static GlobalConfig()
        {
            RuntimeIs462OrHigher = typeof(SqlConnection).GetProperty("ColumnEncryptionKeyCacheTtl") != null;
        }

        private GlobalConfig()
        {
            InitConfig();
        }

        #region Methods

        private static string GetAppConfigValue(string name)
        {
            try
            {
                return ConfigurationManager.AppSettings[name];
            }
            catch
            {
                return null;
            }
        }

        private void InitConfig()
        {
            var str = GetAppConfigValue("SignatureAlgorithm");
            SignatureAlgorithm = string.IsNullOrEmpty(str) ? DEFAULT_SIGNATURE_ALGORITHM : str;

            //RSA
            RsaKeyStrength = ParseInt(GetAppConfigValue("RsaKeyStrength"), MINIMAL_RSA_KEY_STRENGTH);

            //DSA
            DsaKeySize = ParseInt(GetAppConfigValue("DsaKeySize"), MINIMAL_DSA_KEY_SIZE);
            DsaKeyCertainty = ParseInt(GetAppConfigValue("DsaKeyCertainty"), MINIMAL_DSA_KEY_CERTAINTY);

            //EC
            str = GetAppConfigValue("EcCurveName");
            CurveName = string.IsNullOrEmpty(str) ? DEFAULT_CURVE_NAME : str;
        }

        private static int ParseInt(string str, int minValue)
        {
            int outVal;
            return !int.TryParse(str, out outVal) ? minValue : (outVal > minValue ? outVal : minValue);
        }

        #endregion

        public static GlobalConfig Instance => _instance ?? (_instance = new GlobalConfig());

        public int RsaKeyStrength { get; private set; }

        public int DsaKeySize { get; private set; }

        public int DsaKeyCertainty { get; private set; }

        public string CurveName { get; private set; }

        public string SignatureAlgorithm { get; private set; }
    }
}
