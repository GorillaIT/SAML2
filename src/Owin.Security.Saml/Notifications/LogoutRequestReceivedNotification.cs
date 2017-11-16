using Microsoft.Owin;
using Microsoft.Owin.Security.Notifications;
using System;

namespace Owin.Security.Saml.Notifications
{
    public class LogoutRequestReceivedNotification<TMessage, TOptions> : BaseNotification<TOptions>
    {
        public LogoutRequestReceivedNotification(IOwinContext context, TOptions options)
            : base(context, options) { }

        public Exception Exception { get; set; }
        public TMessage ProtocolMessage { get; set; }

    }
}
