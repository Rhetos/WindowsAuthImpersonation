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

using Rhetos.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;

namespace Rhetos.WindowsAuthImpersonation
{
    [Export(typeof(IHomePageSnippet))]
    public class HomePageSnippet : IHomePageSnippet
    {
        private Lazy<string> _snippet;

        public HomePageSnippet()
        {
            _snippet = new Lazy<string>(() =>
                {
                    string filePath = Path.Combine(Paths.ResourcesFolder, "WindowsAuthImpersonation", "HomePageSnippet.html");
                    return File.ReadAllText(filePath, Encoding.Default);
                });
        }

        public string Html
        {
            get
            {
                var html = _snippet.Value;

                string impersonatedUser = GetImpersonatedUser();
                if (impersonatedUser != null)
                {
                    const string impersonatingTag = "<!-- CurrentlyImpersonatingTag -->";

                    var impersonatingSnippet = string.Format(
                        "<p>Currently impersonating user: <b>{0}</b>.</p>",
                        HttpUtility.HtmlEncode(impersonatedUser));

                    html = html.Replace(impersonatingTag, impersonatingSnippet);
                }

                return html;
            }
        }

        public static string GetImpersonatedUser()
        {
            var formsIdentity = (HttpContext.Current.User.Identity as System.Web.Security.FormsIdentity);
            if (formsIdentity != null && formsIdentity.IsAuthenticated)
            {
                string userData = formsIdentity.Ticket.UserData;
                const string prefix = "Impersonating:";
                if (!string.IsNullOrEmpty(userData) && userData.StartsWith(prefix))
                    return userData.Substring(prefix.Length);
            }
            return null;
        }
    }
}
