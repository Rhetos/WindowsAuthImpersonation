using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Rhetos.WindowsAuthImpersonation.Abstractions
{
    public interface IHttpContextAccessor
    {
        HttpContext HttpContext { get; }
    }
}
