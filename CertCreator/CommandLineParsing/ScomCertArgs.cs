using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace CertCreator.CommandLineParsing
{
    [Verb("sc", HelpText = "Create SCOM certificate")]
    internal class ScomCertArgs : IssuedCertArgsBase
    {
    }
}
