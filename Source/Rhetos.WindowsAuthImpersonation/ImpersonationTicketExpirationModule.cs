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
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;
using Autofac;
using Autofac.Integration.Wcf;
using Rhetos.Logging;

namespace Rhetos.WindowsAuthImpersonation
{
    // ideally this class should use DI and utilize existing services, but the way Rhetos/Autofac/Wcf are setup, request lifetimescope
    // does not exist during httpmodule runtime flow
    public class ImpersonationTicketExpirationModule : IHttpModule
    {
        private readonly ILogProvider _logProvider;

        public ImpersonationTicketExpirationModule(ILogProvider logProvider)
        {
            _logProvider = logProvider;
        }

        public void Init(HttpApplication context)
        {
            var log = _logProvider.GetLogger(GetType().Name);
            log.Info(() => $"ImpersonationTicketExpirationModule initializing. Adding EndRequest event handler.");
            context.PreSendRequestHeaders += OnPreSendRequestHeaders;
        }

        public void Dispose()
        {
        }

        private void OnPreSendRequestHeaders(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;

            // this event may be called during authentication requests; ImpersionationService doesn't work (and shouldn't) in that situation
            // so we will skip ticket refreshing as well
            if (!app.Request.IsAuthenticated) return;

            SlideExpirationIfValidTicket();
        }

        public void SlideExpirationIfValidTicket()
        {
            var httpContext = new HttpContextWrapper(HttpContext.Current);
            var log = _logProvider.GetLogger(GetType().Name);

            // if there is already a new value for cookie present in the response, skip the operation
            if (httpContext.Response.Cookies.AllKeys.Contains(FormsAuthentication.FormsCookieName)) return;

            var ticket = TicketUtility.GetExistingTicket(httpContext);
            if (ticket == null) return;

            // if ticket has expired, lets do some housekeeping and remove it from cookies
            if (ticket.Expired)
            {
                log.Trace(() => $"Found expired ticket, removing it.");
                TicketUtility.AddToResponseCookie(null, httpContext);
                return;
            }

            log.Trace(() => $"Found valid existing ticket with expiration: {ticket.Expiration.ToString("s")}");

            var ageLeft = ticket.Expiration - DateTime.Now;

            // do nothing if half of timeout has not yet passed
            if (ageLeft.TotalSeconds > TicketUtility.TicketTimeout.Value.TotalSeconds / 2) return;

            log.Trace(() => $"Cookie age left is {ageLeft.TotalMinutes:0} minutes, refreshing expiration.");
            var newTicket = new FormsAuthenticationTicket(
                ticket.Version,
                ticket.Name,
                ticket.IssueDate,
                DateTime.Now + TicketUtility.TicketTimeout.Value,
                false,
                ticket.UserData,
                ticket.CookiePath);

            TicketUtility.AddToResponseCookie(newTicket, httpContext);
        }
    }
}
