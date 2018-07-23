using Rhetos.AspNetFormsAuth;
using Rhetos.Security;
using Rhetos.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Security;

namespace Rhetos.WindowsAuthImpersonation
{
    [Export(typeof(IUserInfo))]
    public class ImpersonationUserInfo : IUserInfo
    {
        #region IUserInfo implementation

        public bool IsUserRecognized
        {
            get
            {
                return _isUserRecognized.Value;
            }
        }

        public string UserName
        {
            get
            {
                CheckIfUserRecognized();
                return _impersonatedUser.Value ?? _actualUser.Value;
            }
        }

        public string Workstation
        {
            get
            {
                CheckIfUserRecognized();
                return _workstation.Value;
            }
        }

        public string Report()
        {
            CheckIfUserRecognized();
            return _impersonatedUser.Value != null
                ? (_actualUser.Value + " as " + _impersonatedUser.Value + "," + _workstation.Value)
                : _actualUser.Value + "," + _workstation.Value;
        }

        #endregion

        /// <summary>
        /// Returns null if there is no impersonation.
        /// If the current user is impersonating another, this property returns the actual (not impersonated) user that is logged in.
        /// </summary>
        public string ImpersonatedBy
        {
            get
            {
                CheckIfUserRecognized();
                return _impersonatedUser.Value != null ? _actualUser.Value : null;
            }
        }

        private Lazy<bool> _isUserRecognized;

        private Lazy<string> _workstation;

        /// <summary>
        /// The actual (not impersonated) user that is logged in.
        /// </summary>
        private Lazy<string> _actualUser;

        /// <summary>
        /// The impersonated user whose context (including security permissions) is in effect.
        /// Null if there is no impersonation.
        /// </summary>
        private Lazy<string> _impersonatedUser;

        public ImpersonationUserInfo(IWindowsSecurity windowsSecurity)
        {
            _isUserRecognized = new Lazy<bool>(GetIsUserRecognized);
            _actualUser = new Lazy<string>(() => HttpContext.Current.User.Identity.Name);
            _impersonatedUser = new Lazy<string>(GetImpersonatedUser);
            _workstation = new Lazy<string>(() => windowsSecurity.GetClientWorkstation());
        }

        private static bool GetIsUserRecognized()
        {
            return HttpContext.Current != null
                && HttpContext.Current.User != null
                && HttpContext.Current.User.Identity != null
                && HttpContext.Current.User.Identity.IsAuthenticated;
        }

        private string GetImpersonatedUser()
        {
            // For any changes in this function's implementation, consider updating the "GetImpersonatedUser" code snippet in Readme.md.

            var formsIdentity = (HttpContext.Current.User.Identity as FormsIdentity);
            if (formsIdentity != null)
            {
                string userData = formsIdentity.Ticket.UserData;
                if (!string.IsNullOrEmpty(userData) && userData.StartsWith(ImpersonationService.ImpersonatingUserInfoPrefix))
                    return userData.Substring(ImpersonationService.ImpersonatingUserInfoPrefix.Length);
            }
            return null;
        }

        private void CheckIfUserRecognized()
        {
            if (!IsUserRecognized)
                throw new ClientException("User is not authenticated.");
        }
    }
}
