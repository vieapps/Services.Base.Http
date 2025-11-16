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
		bool StopOnError { get; } = "true".IsEquals(UtilityService.GetAppSetting("Authenticator:StopOnError", "false"));

		bool ErrorAsJSON { get; } = "JSON".IsEquals(UtilityService.GetAppSetting("Authenticator:ErrorMode", "HTML"));

		bool AllowOverrideTokenExpires { get; } = "true".IsEquals(UtilityService.GetAppSetting("Authenticator:AllowOverrideTokenExpires", "true"));

		bool AllowWebSocketLateVerification { get; } = "true".IsEquals(UtilityService.GetAppSetting("Authenticator:AllowWebSocketLateVerification", "false"));

		int TokenExpiresAfter { get; } = Int32.TryParse(UtilityService.GetAppSetting("Authenticator:TokenExpiresAfter", "0"), out var expiresAfter) && expiresAfter > -1 ? expiresAfter : 0;

		readonly RequestDelegate nextAsync;

		public Authenticator(RequestDelegate next) => this.nextAsync = next;

		public async Task Invoke(HttpContext context)
		{
			var isDebugLogEnabled = Global.IsDebugLogEnabled || context.ContainsKey("x-logs");
			if (!context.Request.Method.IsEquals("OPTIONS") && !context.Request.Method.IsEquals("HEAD"))
				try
				{
					await this.ProcessRequestAsync(context).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					var url = context.GetRequestUrl();
					if (isDebugLogEnabled || (!url.IsEndsWith(".xml") && !url.IsEndsWith(".json") && !url.IsEndsWith(".txt")))
						await context.WriteLogsAsync("Authentications",
							$"Cannot authenticate [{context.Request.Method} {url}]" + "\r\n" +
							$"- WebSocket: {context.WebSockets.IsWebSocketRequest}" + "\r\n" +
							$"- URI: {context.GetRequestUri()}" + "\r\n" +
							$"- IP: {context.GetRemoteIPAddress()}" + "\r\n" +
							$"- Headers:\r\n\t{context.Request.Headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}"
						, ex).ConfigureAwait(false);
					if (this.StopOnError || context.WebSockets.IsWebSocketRequest)
					{
						if (this.ErrorAsJSON)
							context.WriteError(Global.Logger, ex);
						else
							context.ShowError(ex.GetHttpStatusCode(), ex.Message, ex.GetTypeName(true));
						return;
					}
				}
			await this.nextAsync(context).ConfigureAwait(false);
		}

		async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			var session = context.GetSession();
			var correlationID = context.GetCorrelationID();
			var isDebugLogEnabled = Global.IsDebugLogEnabled || context.ContainsKey("x-logs");

			// already logged-in
			if (context.IsAuthenticated())
			{
				if (isDebugLogEnabled)
					await context.WriteLogsAsync("Authentications", $"Use is already logged-in => [{context.User.Identity.Name}]").ConfigureAwait(false);

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

			// log-in by token
			else
			{
				// prepare authorization token
				var authenticateToken = context.GetParameter("x-app-token") ?? context.GetParameter("x-temp-token");
				if (string.IsNullOrWhiteSpace(authenticateToken) && context.TryGetHeaderParameter("authorization", out authenticateToken))
				{
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"Prepare authorization token => [{authenticateToken}]").ConfigureAwait(false);

					var isBasicToken = authenticateToken.IsStartsWith("Basic");
					authenticateToken = isBasicToken || authenticateToken.IsStartsWith("Bearer") || authenticateToken.IsStartsWith("JWT") ? authenticateToken.ToArray(" ").Last() : null;
					if (authenticateToken != null)
					{
						if (authenticateToken.Trim() == "" || authenticateToken.IsStartsWith("Basic") || authenticateToken.IsStartsWith("Bearer") || authenticateToken.IsStartsWith("JWT"))
							throw new InvalidTokenException("Token is invalid");

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
					}
				}

				// perform log-in with authenticate token
				var isWebSocketRequest = context.WebSockets.IsWebSocketRequest;
				if (!string.IsNullOrWhiteSpace(authenticateToken))
				{
					if (isDebugLogEnabled)
						await context.WriteLogsAsync("Authentications", $"Authenticate with ticket token => [{authenticateToken}]").ConfigureAwait(false);
					var expiresAfter = this.AllowOverrideTokenExpires
						? Int32.TryParse(context.GetParameter("x-app-token-expires"), out var expires) && expires > 0 ? expires : 0
						: this.TokenExpiresAfter;
					await context.UpdateWithAuthenticateTokenAsync(session, authenticateToken, expiresAfter, Global.Logger, "Authentications", correlationID).ConfigureAwait(false);
					context.User = new UserPrincipal(session.User);
					if (context.ContainsKey("x-sign-in") && !isWebSocketRequest)
						await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.User, new AuthenticationProperties { IsPersistent = false }).ConfigureAwait(false);
				}

				// websocket
				else if (isWebSocketRequest)
				{
					var exception = new InvalidRequestException("Request is invalid (token is required for this websocket)");
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
								throw new InvalidRequestException("Request is invalid (token is required for this websocket)", ex);
						}
					}
					else
						throw exception;
				}
			}
		}
	}
}