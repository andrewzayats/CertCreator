using CommandLine;

namespace CertCreator.CommandLineParsing
{
    internal class IssuedCertArgsBase: SingleCertArgsBase
    {
        [Option('i', "isfile", Required = true, HelpText = "Path to the issuer's pfx")]
        public string IssuerFilePath { get; set; }

        [Option('q', "ispass", Required = false, HelpText = "Password for the issuer's pfx")]
        public string IssuerPassword { get; set; }
    }
}
