using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;
//using System.Security.Claims;

namespace RMContamax.Authentication
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        readonly ProtectedSessionStorage _sessionStorage;
        ClaimsPrincipal _anonimous = new ClaimsPrincipal(new ClaimsIdentity());

        string userSesionString = "UserSession";

        public CustomAuthenticationStateProvider(ProtectedSessionStorage sessionStorage, ClaimsPrincipal anonimous)
        {
            _sessionStorage = sessionStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var userSesionStorageResult = await _sessionStorage.GetAsync<UserSesion>(userSesionString);
                var userSession = userSesionStorageResult.Success ? userSesionStorageResult.Value : null;

                if (userSession == null)
                    return await Task.FromResult(new AuthenticationState(_anonimous));

                //var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                //{
                //   new Claim(ClaimTypes.Name, userSession.UserName),
                //   new Claim(ClaimTypes.Role, userSession.Role),
                //}, "CustomAuth"));

                //return await Task.FromResult(new AuthenticationState(claimsPrincipal));
                return await Task.FromResult(new AuthenticationState(_anonimous));
            }
            catch
            { return await Task.FromResult(new AuthenticationState(_anonimous)); }
        }

        public async Task UpdateAuthenticationState(UserSesion userSession)
        {
            ClaimsPrincipal claimsPrincipal;

            if (userSession != null)
            {
                await _sessionStorage.SetAsync(userSesionString, userSession);

                claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                {
                   new Claim(ClaimTypes.Name, userSession.UserName),
                   new Claim(ClaimTypes.Role, userSession.Role),
                }));
            }
            else
            {
                await _sessionStorage.DeleteAsync(userSesionString);
                claimsPrincipal = _anonimous;

                NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
            }
        }
    }
}
