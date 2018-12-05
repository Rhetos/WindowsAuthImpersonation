/*
    Copyright (C) 2014 Omega software d.o.o.

    This file is part of Rhetos.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Web;
using System.Web.Security;
using Rhetos.WindowsAuthImpersonation.Abstractions;

namespace Rhetos.WindowsAuthImpersonation
{
    public class HttpContextAccessor : IHttpContextAccessor
    {
        public bool? IsUserAuthenticated => HttpContext.Current?.User?.Identity?.IsAuthenticated;
        public string UserName => HttpContext.Current?.User?.Identity?.Name;
        public string AuthenticationType => HttpContext.Current?.User?.Identity?.AuthenticationType;

        public FormsAuthenticationTicket GetAuthenticationTicket()
        {
            var authenticationCookie = HttpContext.Current.Request.Cookies[TicketUtility.CookieName];
            if (string.IsNullOrEmpty(authenticationCookie?.Value)) return null;

            var decryptedTicket = FormsAuthentication.Decrypt(authenticationCookie.Value);
            return decryptedTicket;
        }

        public void AddTicketToResponse(FormsAuthenticationTicket authenticationTicket)
        {
            var authenticationCookie = authenticationTicket == null
                ? new HttpCookie(TicketUtility.CookieName) { Expires = DateTime.Now.AddYears(-1) }
                : new HttpCookie(TicketUtility.CookieName, FormsAuthentication.Encrypt(authenticationTicket));

            HttpContext.Current.Response.Cookies.Add(authenticationCookie);
        }
    }
}
