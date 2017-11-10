using Microsoft.Owin;
using SAML2.Bindings;
using SAML2.Config;
using System.IO;

namespace Owin.Security.Saml
{
    public abstract class SamlAbstractEndpointHandler
    {
        protected Saml2Configuration configuration;

        public SamlAbstractEndpointHandler(Saml2Configuration configuration)
        {
            this.configuration = configuration;
        }

        protected HttpArtifactBindingBuilder GetBuilder(IOwinContext context)
        {
            return new HttpArtifactBindingBuilder(
                configuration,
                context.Response.Redirect,
                m => SendResponseMessage(m, context));
        }

        protected static void SendResponseMessage(string message, IOwinContext context)
        {
            context.Response.ContentType = "text/xml";
            using (var writer = new StreamWriter(context.Response.Body))
            {
                writer.Write(HttpSoapBindingBuilder.WrapInSoapEnvelope(message));
                writer.Flush();
                writer.Close();
            }
        }
    }
}
