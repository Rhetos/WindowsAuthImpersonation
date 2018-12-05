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
using System.Web.Configuration;
using System.Web.Security;

namespace Rhetos.WindowsAuthImpersonation
{
    public static class TicketUtility
    {
        public static readonly string SlidingTimeoutConfigurationKey = "ImpersonationTicketSlidingTimeoutMins";
        public static readonly string CookieName = "Rhetos.WindowsAuthImpersonation";
        public static readonly Lazy<TimeSpan> TicketTimeout = new Lazy<TimeSpan>(ReadTimeoutFromConfiguration);

        public static FormsAuthenticationTicket GetExistingTicket(HttpContextBase httpContext)
        {
            var authenticationCookie = httpContext.Request.Cookies[CookieName];
            if (string.IsNullOrEmpty(authenticationCookie?.Value)) return null;

            var decryptedTicket = FormsAuthentication.Decrypt(authenticationCookie.Value);
            return decryptedTicket;
        }

        public static void AddToResponseCookie(FormsAuthenticationTicket authenticationTicket, HttpContextBase httpContext)
        {
            var authenticationCookie = authenticationTicket == null
                ? new HttpCookie(CookieName) { Expires = DateTime.Now.AddYears(-1) }
                : new HttpCookie(CookieName, FormsAuthentication.Encrypt(authenticationTicket));

            httpContext.Response.Cookies.Add(authenticationCookie);
        }

        private static TimeSpan ReadTimeoutFromConfiguration()
        {
            var configValue = WebConfigurationManager.AppSettings[SlidingTimeoutConfigurationKey];
            int timeout;
            if (!int.TryParse(configValue, out timeout))
            {
                timeout = 30;
            }

            return TimeSpan.FromMinutes(timeout);
        }
    }
}
