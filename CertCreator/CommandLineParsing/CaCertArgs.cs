using CommandLine;

namespace CertCreator.CommandLineParsing
{
    [Verb("ca", HelpText = "Create CA certificate")]
    internal class CaCertArgs: SingleCertArgsBase
    {
    }
}
