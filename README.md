# DigiD - SAML2 Single sign-on
Fork of SAML2 owin library originally compatible with Shibboleth. 
This fork is developed to be compatible with the Dutch DigiD. 


## Configuring Owin

```
appBuilder.UseSamlAuthentication(new Owin.Security.Saml.SamlAuthenticationOptions
{
    Configuration = config,                     // Saml2 Core configuration
    RedirectAfterLogin = "/my application URI", // Temporary, will auto-detect later. PRs welcome
});
```

## Configuring the Saml2 Core Library

```
var myconfig = new Saml2Configuration
{
    ServiceProvider = new ServiceProvider
    {
        SigningCertificate = new X509Certificate2(FileEmbeddedResource("cert.pfx"), "pass", MachineKeySet),
        Server = "https://localhost:44333/myapp",
        Id = "https://localhost:44333/myapp",       // EntityId used in SAMLP to identify this SP
        AuthenticationContexts = new AuthenticationContexts(new[] 
        {
            new AuthenticationContext()
            {
                Context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
        })
    },
    AllowedAudienceUris = new List<Uri>(new[] { new Uri("https://localhost:44333/myapp") })
};
// The following URLs are based on the defaults used by the middleware above
myconfig.ServiceProvider.Endpoints.AddRange(new[] {
    new ServiceProviderEndpoint(EndpointType.SignOn, "/myapp/saml2/login", "/core"),
    new ServiceProviderEndpoint(EndpointType.Logout, "/myapp/saml2/logout", "/core"),
    new ServiceProviderEndpoint(EndpointType.Metadata, "/myapp/saml2/metadata")
});
myconfig.IdentityProviders.AddByMetadata("IdPMetadataFile.xml");
myconfig.IdentityProviders.First().OmitAssertionSignatureCheck = true;
myconfig.LoggingFactoryType = "SAML2.Logging.DebugLoggerFactory";
myconfig.IdentityProviders.First().ArtifactResolution = new HttpAuth()
{
    ClientCertificate = new X509Certificate2(FileEmbeddedResource("cert.pfx"), "pass", MachineKeySet)
};
return myconfig;
```
