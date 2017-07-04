using CommandLine;

namespace CertCreator.CommandLineParsing
{
    [Verb("ss", HelpText = "Create self-signed certificate")]
    internal class SelfSignedCertArgs: SingleCertArgsBase
    {
    }
}
