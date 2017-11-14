using SAML2.Schema.Protocol;
using System;

namespace SAML2
{
    /// <summary>
    /// This exception is thrown to indicate an error in the SAML2 toolkit. It was introduced to make it easy to distinguish between
    /// exceptions thrown deliberately by the toolkit, and exceptions that are thrown as the result of bugs.
    /// </summary>
    public class Saml20Exception : Exception
    {
        public StatusCode StatusCode
        {
            private set
            {
                Data.Add("Saml20StatusCode", value);
            }
            get
            {
                return Data.Contains("Saml20StatusCode") ? (StatusCode)Data["Saml20StatusCode"] : null;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Exception"/> class.
        /// </summary>
        public Saml20Exception() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Exception"/> class.
        /// </summary>
        /// <param name="msg">The MSG.</param>
        public Saml20Exception(string msg) : this(msg, (StatusCode)null) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Exception"/> class.
        /// </summary>
        /// <param name="msg">The MSG.</param>
        /// <param name="statusCode">The received status code</param>
        public Saml20Exception(string msg, StatusCode statusCode) : base(msg)
        {
            StatusCode = statusCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Exception"/> class.
        /// </summary>
        /// <param name="msg">A message describing the problem that caused the exception.</param>
        /// <param name="cause">Another exception that may be related to the problem.</param>
        public Saml20Exception(string msg, Exception cause) : this(msg, null, cause) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Exception"/> class.
        /// </summary>
        /// <param name="msg">A message describing the problem that caused the exception.</param>
        /// <param name="statusCode">The received status code</param>
        /// <param name="cause">Another exception that may be related to the problem.</param>
        public Saml20Exception(string msg, StatusCode statusCode, Exception cause) : base(msg, cause)
        {
            StatusCode = statusCode;
        }


    }
}
