using System;

namespace Owin.Security.Saml
{
    /// <summary>
    /// This exception is thrown to indicate an error during (the handeling of) a request.
    /// So that it is easy to handle the exception in a other part of your code.
    /// </summary>
    public class SamlEndpointException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SamlEndpointException"/> class.
        /// </summary>
        public SamlEndpointException(string message, Exception innerException) : base(message, innerException){ }
    }
}
