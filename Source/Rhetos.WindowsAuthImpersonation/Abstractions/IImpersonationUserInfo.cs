using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Rhetos.Utilities;

namespace Rhetos.WindowsAuthImpersonation.Abstractions
{
    public interface IImpersonationUserInfo : IUserInfo
    {
        string ImpersonatedBy { get; }
    }
}
