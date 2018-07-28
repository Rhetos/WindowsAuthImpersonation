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
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Rhetos.Logging;

namespace Rhetos.WindowsAuthImpersonation
{
    public class ImpersonationTicketExpirationModule : IHttpModule
    {
        private readonly Func<ImpersonationService> _impersonationServiceFactory;
        private readonly ILogProvider _logProvider;

        public ImpersonationTicketExpirationModule(Func<ImpersonationService> impersonationServiceFactory, ILogProvider logProvider)
        {
            _impersonationServiceFactory = impersonationServiceFactory;
            _logProvider = logProvider;
        }

        public void Init(HttpApplication context)
        {
            var log = _logProvider.GetLogger(GetType().Name);
            log.Info(() => $"ImpersonationTicketExpirationModule initializing. Adding EndRequest event handler.");
            context.PreSendRequestHeaders += OnEndRequest;
        }

        public void Dispose()
        {
            var log = _logProvider.GetLogger(GetType().Name);
            log.Info(() => $"ImpersonationTicketExpirationModule DISPOSE.");
        }

        private void OnEndRequest(object sender, EventArgs e)
        {
            throw new NotImplementedException("ImpersonationService is instanced in the wrong scope!");
            var app = (HttpApplication)sender;

            // this event may be called during authentication requests; ImpersionationService doesn't work (and shouldn't) in that situation
            // so we will skip ticket refreshing as well
            if (!app.Request.IsAuthenticated) return;

            var log = _logProvider.GetLogger(GetType().Name);
            var impersonationService = _impersonationServiceFactory();
            // log.Info($"OnEndRequest - resolved {impersonationService.GetType().Name}");


            //log.Info($"OnEndRequest[appId={appId}]: {app.Request.RawUrl} Headers: {app.Request.Headers.Count}, {hInfo}");
            
            // log.Info($"OnEndRequest: {app.Context.CurrentHandler?.GetType().Name} {app.Response.StatusCode}.{app.Response.SubStatusCode}, {app.Request.RawUrl}");
            // app.Response.Write("<div>Appended line by custom Sasa module</div>");
            impersonationService.SlideExpirationIfValidTicket();
        }
    }
}
