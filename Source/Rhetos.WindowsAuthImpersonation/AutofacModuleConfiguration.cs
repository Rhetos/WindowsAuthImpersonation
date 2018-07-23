using Autofac;
using Rhetos.Extensibility;
using Rhetos.Security;
using Rhetos.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Text;

namespace Rhetos.WindowsAuthImpersonation
{
    [Export(typeof(Module))]
    public class AutofacModuleConfiguration : Module
    {
        protected override void Load(ContainerBuilder builder)
        {
            builder.RegisterType<ImpersonationService>().InstancePerLifetimeScope();

            Plugins.CheckOverride<IUserInfo, ImpersonationUserInfo>(builder, typeof(WcfWindowsUserInfo));
            builder.RegisterType<ImpersonationUserInfo>().As<IUserInfo>().InstancePerLifetimeScope();

            base.Load(builder);
        }
    }
}
