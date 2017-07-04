using CommandLine;

namespace CertCreator.CommandLineParsing
{
    internal abstract class SingleCertArgsBase
    {
        [Option('n', "subjname", Required = true, HelpText = "Subject name")]
        public string SubjectName { get; set; }

        [Option('o', "outfile", Required = true, HelpText = "Output path of the created certificate's pfx")]
        public string SubjectOutputPath { get; set; }

        [Option('p', "pass", Required = false, HelpText = "Password of the created certificate's pfx")]
        public string SubjectPassword { get; set; }

        [Option('y', "valyears", Required = false, HelpText = "Validity period of the certificate in years (Min=1,Max=40,Default=2)")]
        public int? ValidityYears { get; set; }
    }
}
