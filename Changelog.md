# WindowsAuthImpersonation release notes

## 1.2.0 (2019-09-09)

### Internal improvements

* Implementation of the ImpersonationService is extracted into an interface so it can be overridden when necessary.
* Bugfix: NullReferenceException while handling a different exception in web application.

## 1.1.0 (2018-12-05)

### Internal improvements

* WindowsAuthImpersonation can be used in unit tests (when HttpContext is not available) with a HttpContextAccessorMock

## 1.0.0 (2018-09-07)

### Features

* Impersonation web service API with methods *Impersonate* and *StopImpersonating*.
* Security claims to allow impersonation.
* Simple administration GUI, as a part of the Rhetos server homepage.

See [Readme.md](Readme.md) for more info.
