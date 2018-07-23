# WindowsAuthImpersonation

WindowsAuthImpersonation is a plugin package for [Rhetos development platform](https://github.com/Rhetos/Rhetos).
It allows users to log in as another user when using Windows Authentication.
The impersonation information is persisted only in the standard authentication cookie.

Contents:

* [WindowsAuthImpersonation](#windowsauthimpersonation)
  * [Build](#build)
  * [Installation and configuration](#installation-and-configuration)
    * [Installation](#installation)
    * [Configuring user's permissions](#configuring-users-permissions)
    * [Simple administration GUI](#simple-administration-gui)
  * [Impersonation web service API](#impersonation-web-service-api)
    * [Impersonate](#impersonate)
    * [StopImpersonating](#stopimpersonating)
  * [Implementing web GUI](#implementing-web-gui)

## Build

**Note:** This package is already available at the [NuGet.org](https://www.nuget.org/) online gallery.
You don't need to build it from source in order to use it in your application.

Development environment:
* Visual Studio 2015 or newer.

To build the package from source, run `Build.bat`.
The build output is a NuGet package in the "Install" subfolder.

## Installation and configuration

### Installation

To install this package to a Rhetos server, add it to the Rhetos server's *RhetosPackages.config* file
and make sure the NuGet package location is listed in the *RhetosPackageSources.config* file.

* The package ID is "**Rhetos.WindowsAuthImpersonation**".
  This package is available at the [NuGet.org](https://www.nuget.org/) online gallery.
  It can be downloaded or installed directly from there.
* For more information, see [Installing plugin packages](https://github.com/Rhetos/Rhetos/wiki/Installing-plugin-packages).

### Configuring user's permissions

The following security claims are used in the impersonation web service:

* `WindowsAuthImpersonation.Impersonate` : `Execute`
  * A user with this claim is allowed to impersonate another user (execute the `Impersonate` web method).
* `WindowsAuthImpersonation.Impersonate` : `IncreasePermissions`
  * A user with this claim is allowed to **impersonate another user that has more permissions** than the original user.
  This claim is **not assigned** by default to the admin user.
* `WindowsAuthImpersonation.StopImpersonating` : `Execute`
  * Should be added to all used with claim `WindowsAuthImpersonation.Impersonate` `Execute`.

### Simple administration GUI

For testing and administration, a simple web GUI is available at the Rhetos server homepage under *WindowsAuthImpersonation* header.

## Impersonation web service API

The JSON service is available at URI `<rhetos server>/Resources/WindowsAuthImpersonation/Impersonation`, with the following methods.

### Impersonate

Activates impersonation for the currently logged in user to act as the given `ImpersonatedUser`.

* Interface: `(string ImpersonatedUser) -> void`
* Requires `Impersonate` security claim (see "Configuring user's permissions").
* On successful impersonation, the server response will contain the standard authentication cookie,
  containing the impersonation information.
  The client browser will automatically use the cookie for following requests.
* Response data is empty the impersonation is successful,
  or an error message (*string*) with HTTP error code 4* or 5* in case of an error.

### StopImpersonating

The user stays logged in, but the impersonation of deactivated.

* No request data is needed. Response is empty.

## Implementing web GUI

Web application that [shares user authentication](https://github.com/Rhetos/AspNetFormsAuth/blob/master/Readme.md#sharing-the-authentication-across-web-applications)
with Rhetos server may access the impersonation information and show it in the GUI.

To find out if the current user impersonates another, use the following code snippet:

```C#
// (the project must reference **System.Web.dll**)

/// <summary>
/// Returns the impersonated user whose context (including security permissions) is in effect.
/// Returns null if there is no impersonation.
/// </summary>
public static string GetImpersonatedUser()
{
    var formsIdentity = (System.Web.HttpContext.Current.User.Identity as System.Web.Security.FormsIdentity);
    if (formsIdentity != null && formsIdentity.IsAuthenticated)
    {
        string userData = formsIdentity.Ticket.UserData;
        const string prefix = "Impersonating:";
        if (!string.IsNullOrEmpty(userData) && userData.StartsWith(prefix))
            return userData.Substring(prefix.Length);
    }
    return null;
}
```
