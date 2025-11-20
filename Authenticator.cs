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

namespace net.vieapps.Services
{
	/// <summary>
	/// Middleware for authenticating the request pipeline via authorization token
	/// </summary>
	public sealed class Authenticator
	{
		readonly RequestDelegate NextAsync;
		readonly bool StopOnError;
		readonly bool ErrorAsJson;
		readonly bool AllowOverrideTokenExpires;
		readonly int TokenExpiresAfter;
		readonly bool AllowWebSocketLateVerification;

		public Authenticator(RequestDelegate next, bool? stopOnError = null, bool? errorAsJson = null, bool? allowOverrideTokenExpires = null, int? tokenExpiresAfter = null, bool? allowWebSocketLateVerification = null)
		{
			this.NextAsync = next;
			this.StopOnError = stopOnError != null ? stopOnError.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:StopOnError", "false"));
			this.ErrorAsJson = errorAsJson != null ? errorAsJson.Value : "JSON".IsEquals(UtilityService.GetAppSetting("Authenticator:ErrorMode", "HTML"));
			this.AllowOverrideTokenExpires = allowOverrideTokenExpires != null ? allowOverrideTokenExpires.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:AllowOverrideTokenExpires", "true"));
			this.TokenExpiresAfter = tokenExpiresAfter != null && tokenExpiresAfter.Value > 0 ? tokenExpiresAfter.Value : Int32.TryParse(UtilityService.GetAppSetting("Authenticator:TokenExpiresAfter", "0"), out var expiresAfter) && expiresAfter > -1 ? expiresAfter : 0;
			this.AllowWebSocketLateVerification = allowWebSocketLateVerification != null ? allowWebSocketLateVerification.Value : "true".IsEquals(UtilityService.GetAppSetting("Authenticator:AllowWebSocketLateVerification", "false"));
		}

		public async Task Invoke(HttpContext context)
		{
			if (!context.Request.Method.IsEquals("OPTIONS"))
			{
				var isDebugLogEnabled = Global.IsDebugLogEnabled || context.ContainsKey("x-logs");
				try
				{
					await this.ProcessRequestAsync(context).ConfigureAwait(false);
					if (isDebugLogEnabled && context.IsAuthenticated())
						await context.WriteLogsAsync("Authentications", $"Request is authenticated [{context.User.Identity.Name}]", null).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					var url = context.GetRequestUrl();
					var isWebSocketRequest = context.WebSockets.IsWebSocketRequest;
					if (isDebugLogEnabled || (!url.IsEndsWith(".xml") && !url.IsEndsWith(".json") && !url.IsEndsWith(".txt")))
						await context.WriteLogsAsync("Authentications",
							$"Authentication failed [{context.Request.Method} {url} - WS: {isWebSocketRequest}]" + "\r\n" +
							$"- IP: {context.GetRemoteIPAddress()}" + "\r\n" +
							$"- Headers: " + (isDebugLogEnabled ? $"\r\n\t{context.Request.Headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}" : $"{context.GetHeaderParameter("Authorization") ?? context.GetParameter("x-app-token")}")
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

		async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			var session = context.GetSession();
			var correlationID = context.GetCorrelationID();
			var isDebugLogEnabled = Global.IsDebugLogEnabled || context.ContainsKey("x-logs");

			// already authenticated
			if (context.IsAuthenticated())
			{
				if (isDebugLogEnabled)
					await context.WriteLogsAsync("Authentications", $"Use is already logged-in [{context.User.Identity.Name}]").ConfigureAwait(false);

				if (string.IsNullOrWhiteSpace(session.User.ID) && string.IsNullOrWhiteSpace(session.User.SessionID))
				{
					session.User = context.GetUser();
					session.SessionID = session.User.SessionID = !string.IsNullOrWhiteSpace(session.SessionID)
						? session.SessionID
						: UtilityService.NewUUID;
				}
				else
				{
					session.SessionID = session.User.SessionID = !string.IsNullOrWhiteSpace(session.User.SessionID)
						? session.User.SessionID
						: !string.IsNullOrWhiteSpace(session.SessionID)
							? session.SessionID
							: UtilityService.NewUUID;
					context.User = new UserPrincipal(session.User);
				}
			}

			// authenticate by token
			else
			{
				// prepare token
				var authenticateToken = context.GetParameter("x-app-token") ?? context.GetParameter("x-temp-token");
				var gotAuthorizationToken = false;
				if (string.IsNullOrWhiteSpace(authenticateToken) && context.TryGetHeaderParameter("authorization", out authenticateToken))
				{
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"Prepare token from authorization header => [{authenticateToken}]").ConfigureAwait(false);

					var isBasicToken = authenticateToken.IsStartsWith("Basic");
					authenticateToken = isBasicToken || authenticateToken.IsStartsWith("Bearer") || authenticateToken.IsStartsWith("JWT") ? authenticateToken.ToArray(" ").Last() : null;
					if (authenticateToken != null)
					{
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
						gotAuthorizationToken = true;
					}
				}

				// authenticate
				var isWebSocketRequest = context.WebSockets.IsWebSocketRequest;
				if (!string.IsNullOrWhiteSpace(authenticateToken))
				{
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"Authenticate => [{authenticateToken}]").ConfigureAwait(false);

					if (!gotAuthorizationToken)
					{
						var expiresAfter = this.AllowOverrideTokenExpires
							? Int32.TryParse(context.GetParameter("x-app-token-expires"), out var expires) && expires > 0 ? expires : 0
							: this.TokenExpiresAfter;
						await context.UpdateWithAuthenticateTokenAsync(session, authenticateToken, expiresAfter, Global.Logger, "Authentications", correlationID).ConfigureAwait(false);
					}

					context.User = new UserPrincipal(session.User);
					if (context.ContainsKey("x-sign-in") && !isWebSocketRequest)
						await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.User, new AuthenticationProperties { IsPersistent = false }).ConfigureAwait(false);
				}

				// websocket with no authenticate token
				else if (isWebSocketRequest)
				{
					var exception = new InvalidRequestException("Request is invalid (authorization token is required)");
					if (this.AllowWebSocketLateVerification)
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
							if (ex is InvalidSessionException || ex is InvalidTokenSignatureException || ex is InvalidTokenException || ex is TokenNotFoundException || ex is TokenExpiredException || ex is TokenRevokedException)
								throw;
							else
								throw new InvalidRequestException("Request is invalid (authorization token is required)", ex);
						}
					}
					else
						throw exception;
				}
			}
		}
	}
}