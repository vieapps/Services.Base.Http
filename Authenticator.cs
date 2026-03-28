#region Related components
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services
{
	/// <summary>
	/// Middleware for authenticating the request pipeline
	/// </summary>
	public sealed class Authenticator
	{
		readonly RequestDelegate NextAsync;
		readonly bool StopOnError;
		readonly bool ErrorAsJson;
		readonly bool AllowOverrideTokenExpires;
		readonly int TokenExpiresAfter;
		readonly bool AllowWebSocketLateVerification;
		readonly bool RequireAuthenticated;

		public Authenticator(RequestDelegate next, bool? stopOnError = null, bool? errorAsJson = null, bool? allowOverrideTokenExpires = null, int? tokenExpiresAfter = null, bool? allowWebSocketLateVerification = null, bool? requireAuthenticated = null)
		{
			this.NextAsync = next;
			this.StopOnError = stopOnError != null ? stopOnError.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:StopOnError", "false"));
			this.ErrorAsJson = errorAsJson != null ? errorAsJson.Value : "JSON".IsEquals(UtilityService.GetAppSetting("Authenticator:ErrorMode", "HTML"));
			this.AllowOverrideTokenExpires = allowOverrideTokenExpires != null ? allowOverrideTokenExpires.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:AllowOverrideTokenExpires", "true"));
			this.TokenExpiresAfter = tokenExpiresAfter != null && tokenExpiresAfter.Value > 0 ? tokenExpiresAfter.Value : Int32.TryParse(UtilityService.GetAppSetting("Authenticator:TokenExpiresAfter", "0"), out var expiresAfter) && expiresAfter > -1 ? expiresAfter : 0;
			this.AllowWebSocketLateVerification = allowWebSocketLateVerification != null ? allowWebSocketLateVerification.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:AllowWebSocketLateVerification", "false"));
			this.RequireAuthenticated = requireAuthenticated != null ? requireAuthenticated.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:RequireAuthenticated", "false"));
		}

		public async Task Invoke(HttpContext context)
		{
			if (!context.Request.Method.IsEquals("OPTIONS"))
			{
				var isDebugLogEnabled = Global.IsDebugLogEnabled || context.ContainsKey("x-logs") || context.ContainsKey("x-auth-logs");
				try
				{
					await context.AuthenticateRequestAsync(this.AllowOverrideTokenExpires, this.TokenExpiresAfter, this.AllowWebSocketLateVerification, this.RequireAuthenticated).ConfigureAwait(false);
					if (isDebugLogEnabled && context.IsAuthenticated())
						await context.WriteLogsAsync("Authentications", $"Request is authenticated [Identity: {context.User.Identity.Name}]", null).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					var url = context.GetRequestUrl();
					var isWebSocketRequest = context.WebSockets.IsWebSocketRequest;
					if (isDebugLogEnabled || (!url.IsEndsWith(".xml") && !url.IsEndsWith(".json") && !url.IsEndsWith(".txt")))
						await context.WriteLogsAsync("Authentications",
							$"Authentication failed => {ex.Message}" + "\r\n" +
							$"- {context.Request.Method} {url} (WebSocket: {isWebSocketRequest})" + "\r\n" +
							$"- IP: {context.GetRemoteIPAddress()}" + "\r\n" +
							$"- Headers: " + (isDebugLogEnabled ? $"\r\n\t{context.Request.Headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}" : $"{context.GetHeaderParameter("Authorization") ?? context.GetParameter("x-app-token") ?? context.GetParameter("x-temp-token")}")
						, ex).ConfigureAwait(false);
					if (this.StopOnError || isWebSocketRequest)
					{
						if (this.ErrorAsJson)
							context.WriteError(Global.Logger, ex);
						else
							context.ShowError(ex.GetHttpStatusCode(), ex.Message, ex.GetTypeName(true));
						return;
					}
				}
			}
			await this.NextAsync(context).ConfigureAwait(false);
		}
	}

	public static class AuthenticatorExtentions
	{
		/// <summary>
		/// Performs the authenticate process of this request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="allowOverrideTokenExpires"></param>
		/// <param name="tokenExpiresAfter"></param>
		/// <param name="allowWebSocketLateVerification"></param>
		/// <param name="requireAuthenticated"></param>
		/// <returns></returns>
		public static async Task AuthenticateRequestAsync(this HttpContext context, bool allowOverrideTokenExpires = true, int tokenExpiresAfter = 0, bool allowWebSocketLateVerification = true, bool requireAuthenticated = false)
		{
			// prepare
			var session = context.GetSession();
			var correlationID = context.GetCorrelationID();
			var isDebugLogEnabled = Global.IsDebugLogEnabled || context.ContainsKey("x-logs") || context.ContainsKey("x-auth-logs");

			// already authenticated
			if (context.IsAuthenticated())
			{
				if (context.User.Identity is IUser user)
					session.User = context.GetUser();
				else
				{
					session.User = new User(context.User.Identity.Name, session.SessionID, null, null, "APIs");
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"Call service to update roles/privileges\r\nIdentity: {context.User.Identity.Name}]\r\nSession Info: {session.ToJson()}").ConfigureAwait(false);
					await context.UpdateWithAccessTokenAsync(session).ConfigureAwait(false);
					context.User = new UserPrincipal(session.User);
				}
				if (isDebugLogEnabled)
					await context.WriteLogsAsync("Authentications", $"User info (already logged-in) was updated\r\nIdentity: {context.User.Identity.Name}]\r\nSession Info: {session.ToJson()}").ConfigureAwait(false);
			}

			// need to authenticate by provided token
			else
			{
				// prepare token
				var authenticateToken = context.GetParameter("x-app-token") ?? context.GetParameter("x-temp-token");
				var gotAuthorizationToken = false;
				if (string.IsNullOrWhiteSpace(authenticateToken))
				{
					bool isBasicToken;
					if (context.TryGetHeaderParameter("authorization", out authenticateToken))
					{
						isBasicToken = authenticateToken.IsStartsWith("Basic");
						authenticateToken = isBasicToken || authenticateToken.IsStartsWith("Bearer") || authenticateToken.IsStartsWith("JWT") ? authenticateToken.ToArray(" ").Last() : null;
					}
					else
					{
						authenticateToken = context.GetParameter("x-basic-token") ?? context.GetParameter("x-bearer-token");
						isBasicToken = authenticateToken != null && context.ContainsKey("x-basic-token");
					}

					if (authenticateToken != null)
					{
						if (isDebugLogEnabled)
							await context.WriteLogsAsync("Authentications", $"Prepare token from authorization token => [{authenticateToken}]").ConfigureAwait(false);

						if (authenticateToken.Trim() == "" || authenticateToken.IsStartsWith("Basic") || authenticateToken.IsStartsWith("Bearer") || authenticateToken.IsStartsWith("JWT"))
							throw new InvalidTokenException("Authorization token is invalid");

						var response = await new RequestInfo(session, "Users", "Token", "GET")
						{
							Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
							Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
							{
								["x-authorization-token"] = authenticateToken,
								["x-authorization-mode"] = isBasicToken ? "Basic" : "Bearer",
								["x-authorization-signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey)
							},
							CorrelationID = correlationID
						}.CallServiceAsync(Global.CancellationToken).ConfigureAwait(false);

						authenticateToken = response.Get<string>("Token");
						session.Fill(response.Get<JObject>("Session"));
						context.Request.Headers.Append("x-app-token", authenticateToken);
						gotAuthorizationToken = true;
					}
				}

				// authenticate
				var isWebSocketRequest = context.WebSockets.IsWebSocketRequest;
				if (!string.IsNullOrWhiteSpace(authenticateToken))
				{
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"Do authenticate => [{authenticateToken}]").ConfigureAwait(false);

					if (!gotAuthorizationToken)
					{
						var expiresAfter = allowOverrideTokenExpires
							? Int32.TryParse(context.GetParameter("x-app-token-expires"), out var expires) && expires > 0 ? expires : 0
							: tokenExpiresAfter;
						await context.UpdateWithAuthenticateTokenAsync(session, authenticateToken, expiresAfter, Global.Logger, "Authentications", correlationID).ConfigureAwait(false);
					}
					else
					{
						session.SessionID = string.IsNullOrWhiteSpace(session.SessionID) ? session.User.SessionID : session.SessionID;
						session.DeviceID = string.IsNullOrWhiteSpace(session.DeviceID) ? $"{UtilityService.NewUUID}@vieapps-ngx" : session.DeviceID;
					}

					context.User = new UserPrincipal(session.User);
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"User info was updated\r\nIdentity: {context.User.Identity.Name}]\r\nSession Info: {session.ToJson()}").ConfigureAwait(false);

					if (!isWebSocketRequest && context.ContainsKey("x-sign-in"))
						await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.User, new AuthenticationProperties { IsPersistent = false }).ConfigureAwait(false);
				}

				// websocket with no authenticate token
				else if (isWebSocketRequest)
				{
					var exception = new InvalidRequestException("Request is invalid (authorization token is required)");
					if (allowWebSocketLateVerification)
					{
						var sessionID = context.GetParameter("x-session-id");
						if (string.IsNullOrWhiteSpace(sessionID))
							throw exception;

						try
						{
							session.SessionID = sessionID.Url64Decode();
							if (!await session.IsSessionExistAsync(Global.Logger, "Authentications", correlationID).ConfigureAwait(false))
								throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");

							sessionID = session.GetEncryptedID();
							if (!sessionID.Equals(session.SessionID))
								throw new InvalidSessionException("Session is invalid (The session is not issued by the system)");
						}
						catch (Exception ex)
						{
							throw ex is InvalidSessionException || ex is InvalidTokenSignatureException || ex is InvalidTokenException || ex is TokenNotFoundException || ex is TokenExpiredException || ex is TokenRevokedException ? ex : new InvalidRequestException("Request is invalid (authorization token is required)", ex);
						}
					}
					else
						throw exception;
				}
			}

			// required
			if (requireAuthenticated && !context.IsAuthenticated())
				throw new UnauthorizedException();
		}
	}
}