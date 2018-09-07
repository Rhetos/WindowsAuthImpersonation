# WindowsAuthImpersonation

WindowsAuthImpersonation is a plugin package for [Rhetos development platform](https://github.com/Rhetos/Rhetos).
It allows users to issue requests as another user when using Windows Authentication and HTTP client with cookie support.
The impersonation information is persisted in the custom authentication cookie.

Most common scenario is using this plugin together with with [RestGenerator](https://github.com/Rhetos/RestGenerator) plugin for RESTful access to Rhetos.

Contents:

* [Build](#build)
* [Installation and configuration](#installation-and-configuration)
  * [Installation](#installation)
  * [Configuring user's permissions](#configuring-users-permissions)
  * [Simple administration GUI](#simple-administration-gui)
  * [Sliding expiration timeout](#sliding-expiration-timeout)
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

* `WindowsAuthImpersonation.Impersonate` : `AllowImpersonation`
  * A user with this claim is allowed to impersonate another user (execute the `Impersonate` web method).
* `WindowsAuthImpersonation.Impersonate` : `IncreasePermissions`
  * A user with this claim is allowed to **impersonate another user that has more permissions** than the original user.
  This claim is **not assigned** by default to the admin user.

### Simple administration GUI

For testing and administration, a simple web GUI is available at the Rhetos server homepage under *WindowsAuthImpersonation* header.

### Sliding expiration timeout

Plugin implements a cookie sliding expiration behavior. It will renew cookies (reset expiration) on requests, so only idle clients' cookies will expire.
Idle expiration timeout can be configured via Rhetos web.config configuration file by adding a setting:

```xml
  <appSettings>
    <add key="ImpersonationTicketSlidingTimeoutMins" value="30" />
  </appSettings>
```

Expiration value is specified in minutes and defaults to 30.

## Impersonation web service API

The JSON service is available at URI `<rhetos server>/Resources/WindowsAuthImpersonation/Impersonation`, with the following methods.

### Impersonate

Activates impersonation for the currently logged in user to act as the given `ImpersonatedUser`.

* Interface: `(string ImpersonatedUser) -> void`
* Requires `WindowsAuthImpersonation.Impersonate` security claim (see "Configuring user's permissions").
* On successful impersonation, the server response will contain cookie with impersonation information. Use this cookie on subsequent requests to access Rhetos as impersonated user. Cookie has a sliding expiration so the client should update it if Rhetos returns updated cookie on any request. If the client is a browser, cookie handling will be done automatically.
* Response data is empty the impersonation is successful, or an error message (*string*) with HTTP error code 4* or 5* in case of an error.

### StopImpersonating

Impersonation is deactivated and the impersonation cookie is invalidated.

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
    const string cookieName = "Rhetos.WindowsAuthImpersonation";
    const string impersonationPrefix = "Impersonating:";

    var authenticationCookie = HttpContext.Current?.Request?.Cookies[cookieName];
    if (string.IsNullOrEmpty(authenticationCookie?.Value)) return null;

    var decryptedTicket = FormsAuthentication.Decrypt(authenticationCookie.Value);

    if (decryptedTicket.Expired) return null;
    if (string.IsNullOrEmpty(decryptedTicket.Name) || decryptedTicket.Name != HttpContext.Current.User?.Identity?.Name) return null;
    if (string.IsNullOrEmpty(decryptedTicket.UserData) || !decryptedTicket.UserData.StartsWith(impersonationPrefix)) return null;

    return decryptedTicket.UserData.Substring(impersonationPrefix.Length);
}
```
