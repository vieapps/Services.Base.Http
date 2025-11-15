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

		int TokenExpiresAfter { get; } = Int32.TryParse(UtilityService.GetAppSetting("Authenticator:TokenExpiresAfter", "0"), out var expiresAfter) && expiresAfter > -1 ? expiresAfter : 0;

		readonly RequestDelegate nextAsync;

		public Authenticator(RequestDelegate next) => this.nextAsync = next;

		public async Task Invoke(HttpContext context)
		{
			if (!context.Request.Method.IsEquals("OPTIONS") && !context.Request.Method.IsEquals("HEAD"))
				try
				{
					await this.ProcessRequestAsync(context).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					var url = context.GetRequestUrl();
					if (!url.IsEndsWith(".xml") && !url.IsEndsWith(".json"))
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

			// already logged-in (by cookie)
			if (context.IsAuthenticated())
			{
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

			// perform log-in by authenticate token
			else
			{
				// prepare authenticate token
				var authenticateToken = context.GetParameter("x-app-token") ?? context.GetParameter("x-temp-token");
				if (string.IsNullOrWhiteSpace(authenticateToken) && context.TryGetHeaderParameter("authorization", out authenticateToken))
				{
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
					var expiresAfter = this.AllowOverrideTokenExpires
						? Int32.TryParse(context.GetParameter("x-app-token-expires"), out var expires) && expires > 0 ? expires : 0
						: this.TokenExpiresAfter;
					await context.UpdateWithAuthenticateTokenAsync(session, authenticateToken, expiresAfter, Global.Logger, "Authentications", correlationID).ConfigureAwait(false);
					context.User = new UserPrincipal(session.User);
					if (context.ContainsKey("x-sign-in") && !isWebSocketRequest)
						await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, context.User, new AuthenticationProperties { IsPersistent = false }).ConfigureAwait(false);
				}

				// websocket => token is required
				else if (isWebSocketRequest)
					throw new InvalidRequestException("Request is invalid (token is required for this websocket).");
			}

			// update session info
			if (string.IsNullOrWhiteSpace(session.DeviceID))
			{
				if (context.TryGetParameter("x-device-id", out var value))
					try
					{
						session.DeviceID = value.Url64Decode();
					}
					catch
					{
						session.DeviceID = value;
					}
				else if (context.TryGetParameter("x-did", out value))
					try
					{
						session.DeviceID = value.Url64Decode();
					}
					catch { }
				session.DeviceID = string.IsNullOrWhiteSpace(session.DeviceID) ? $"{UtilityService.NewUUID}@vieapps-ngx" : session.DeviceID;
			}
			else
				try
				{
					session.DeviceID = session.DeviceID.Url64Decode();
				}
				catch { }

			if (string.IsNullOrWhiteSpace(session.AppName))
			{
				if (context.TryGetParameter("x-app-name", out var value))
					try
					{
						session.AppName = value.Url64Decode();
					}
					catch
					{
						session.AppName = value;
					}
				else
					session.AppName = "NGX Websites";
			}
			else
				try
				{
					session.AppName = session.AppName.Url64Decode();
				}
				catch { }

			if (string.IsNullOrWhiteSpace(session.AppPlatform))
			{
				if (context.TryGetParameter("x-app-platform", out var value))
					try
					{
						session.AppPlatform = value.Url64Decode();
					}
					catch
					{
						session.AppPlatform = value;
					}
				else
					session.AppPlatform = "Desktop PWA";
			}
			else
				try
				{
					session.AppPlatform = session.AppPlatform.Url64Decode();
				}
				catch { }
		}
	}
}