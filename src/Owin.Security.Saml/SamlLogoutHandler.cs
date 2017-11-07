using Microsoft.Owin;
using SAML2;
using SAML2.Logging;
using SAML2.Protocol;
using System;
using System.Threading.Tasks;

namespace Owin.Security.Saml
{
    public class SamlLogoutHandler
    {
        private static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(typeof(SamlLoginHandler));

        private readonly SamlAuthenticationOptions options;

        public SamlLogoutHandler(SamlAuthenticationOptions options)
        {
            if (options == null) throw new ArgumentNullException("options");
            this.options = options;
        }

        public async Task<bool> Invoke(IOwinContext context)
        {
            Logger.Debug(TraceMessages.LogoutHandlerCalled);

            // Some IDP's are known to fail to set an actual value in the SOAPAction header
            // so we just check for the existence of the header field.
            //if (Array.Exists(context.Request.Headers.AllKeys, s => s == SoapConstants.SoapAction))
            //{
            //    HandleSoap(context, context.Request.InputStream, config);
            //    return;
            //}

            var requestParams = context.Request.GetRequestParameters().ToNameValueCollection();

            //if (!string.IsNullOrEmpty(requestParams["SAMLart"]))
            //{
            //    HandleArtifact(context, ConfigurationFactory.Instance.Configuration, HandleSoap);
            //    return;
            //}

            if (!string.IsNullOrEmpty(requestParams["SAMLResponse"]))
            {
                HandleResponse(context);

                return await Task.FromResult(true);
            }
            //else if (!string.IsNullOrEmpty(context.Request.Params["SAMLRequest"]))
            //{
            //    HandleRequest(context);
            //}
            //else
            //{
            //    IdentityProvider idpEndpoint = null;

            //    // context.Session[IDPLoginSessionKey] may be null if IIS has been restarted
            //    if (context.Session[IdpSessionIdKey] != null)
            //    {
            //        idpEndpoint = IdpSelectionUtil.RetrieveIDPConfiguration((string)context.Session[IdpLoginSessionKey], config);
            //    }

            //    if (idpEndpoint == null)
            //    {
            //        // TODO: Reconsider how to accomplish this.
            //        context.User = null;
            //        FormsAuthentication.SignOut();

            //        Logger.ErrorFormat(ErrorMessages.UnknownIdentityProvider, string.Empty);
            //        throw new Saml20Exception(string.Format(ErrorMessages.UnknownIdentityProvider, string.Empty));
            //    }

            //    TransferClient(idpEndpoint, context, config);
            //}

            throw new NotImplementedException();
        }

        /// <summary>
        /// Handles the response.
        /// </summary>
        /// <param name="context">The context.</param>
        private void HandleResponse(IOwinContext context)
        {
            var requestType = context.Request.Method;
            var requestParams = context.Request.GetRequestParameters().ToNameValueCollection();
            var requestUrl = context.Request.Uri;
            new Logout(Logger, options.Configuration).ValidateLogoutRequest(requestType, requestParams, requestUrl);
            // Log the user out locally
            DoLogout(context, false);

            // maybe possible from relay state if not set here
            context.Response.Redirect(options.RedirectAfterLogoff ?? "/");
        }

        /// <summary>
        /// Handles executing the logout.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="idpInitiated">if set to <c>true</c> identity provider is initiated.</param>
        private void DoLogout(IOwinContext context, bool idpInitiated = false)
        {
            Logger.Debug(TraceMessages.LogoutActionsExecuting);
            // TODO: Event for logout actions
            //foreach (var action in Actions.Actions.GetActions(config))
            //{
            //    Logger.DebugFormat("{0}.{1} called", action.GetType(), "LogoutAction()");

            //    action.LogoutAction(this, context, idpInitiated);

            //    Logger.DebugFormat("{0}.{1} finished", action.GetType(), "LogoutAction()");
            //}
        }

    }
}
