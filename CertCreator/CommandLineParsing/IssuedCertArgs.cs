using System.Collections.Generic;
using CommandLine;

namespace CertCreator.CommandLineParsing
{
    [Verb("is", HelpText = "Create certificate issued by CA")]
    internal class IssuedCertArgs: IssuedCertArgsBase
    {
        [Option('a', "san", Required = false, HelpText = "SAN names")]
        public IEnumerable<string> SanNames { get; set; }
    }
}
