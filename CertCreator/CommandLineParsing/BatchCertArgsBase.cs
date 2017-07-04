using CommandLine;

namespace CertCreator.CommandLineParsing
{
    internal class BatchCertArgsBase
    {
        [Option('d', "outdir", Required = true, HelpText = "Path to the output directory")]
        public string OutputDir { get; set; }

        [Option('p', "pass", Required = false, HelpText = "Password of the created certificate's pfx")]
        public string SubjectPassword { get; set; }

        [Option('y', "valyears", Required = false, HelpText = "Validity period of the certificate in years (Min=1,Max=40,Default=2)")]
        public int? ValidityYears { get; set; }
    }
}
