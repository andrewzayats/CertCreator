using CommandLine;

namespace CertCreator.CommandLineParsing
{
    [Verb("bis", HelpText = "Create multiple issued certificates")]
    internal class BatchIssuedCertArgs: BatchCertArgsBase
    {
        [Option('i', "isfile", Required = true, HelpText = "Path to the issuer's pfx")]
        public string IssuerFilePath { get; set; }

        [Option('q', "ispass", Required = false, HelpText = "Password for the issuer's pfx")]
        public string IssuerPassword { get; set; }

        [Option("rb", Required = true, HelpText = "The first value of the range")]
        public int RangeBegin { get; set; }

        [Option("re", Required = true, HelpText = "The last value of the range")]
        public int RangeEnd { get; set; }

        [Option("pr", Required = true, HelpText = "Common name prefix")]
        public string NamePrefix { get; set; }

        [Option("zn", Required = false, Default = 0, HelpText = "Count of number's leading zeros")]
        public int LeadingZeros { get; set; }
    }
}
