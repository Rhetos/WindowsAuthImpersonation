using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Rhetos.WindowsAuthImpersonation.Abstractions;

namespace Rhetos.WindowsAuthImpersonation
{
    public class HttpContextAccessor : IHttpContextAccessor
    {
        public HttpContext HttpContext => HttpContext.Current;
    }
}
