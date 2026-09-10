#region Related components
using System;
using System.Net;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services
{
	public static class McpHandlerExtensions
	{
		static List<string> SupportedProtocolVersions { get; } = new List<string> { "2026-07-28" };

		static ConcurrentDictionary<string, MCP.Settings> Settings { get; } = new ConcurrentDictionary<string, MCP.Settings>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Gets or Sets the time-to-live (miliseconds)
		/// </summary>
		public static long McpTimeToLive { get; set; } = 1800000;

		static string Decode(this string value)
		{
			if (!string.IsNullOrWhiteSpace(value) && value.IsStartsWith("=?base64?") && value.EndsWith("?="))
				try
				{
					var encoded = value.Substring(9, value.Length - 11);
					return encoded.FromBase64();
				}
				catch (Exception ex)
				{
					throw new MCP.InvalidHeaderException("Invalid Base64-encoded MCP header value", ex);
				}
			return value;
		}

		/// <summary>
		/// Gets the params of RequestInfo
		/// </summary>
		/// <param name="context"></param>
		/// <param name="systemID"></param>
		/// <returns></returns>
		public static (Session Session, Dictionary<string, string> Query, Dictionary<string, string> Headers, Dictionary<string, string> Extra, string CorrelationID) GetRequestInfoParams(this HttpContext context, string systemID = null)
		{
			var session = context.GetSession();
			var query = context.Request.QueryString.ToDictionary();
			var headers = context.Request.Headers.ToDictionary(header =>
			{
				header["x-use-cursor"] = "yes";
				header["x-requester"] = "vieapps-ngx-mcp";
				if (!string.IsNullOrWhiteSpace(systemID))
					header["x-system-id"] = systemID;
			});
			var extra = new Dictionary<string, string>
			{
				["x-mcp-request-method"] = context.GetHeaderParameter("MCP-Method")
			};
			var mcpName = context.GetHeaderParameter("MCP-Name")?.Decode();
			if (!string.IsNullOrWhiteSpace(mcpName))
				extra["x-mcp-request-name"] = mcpName;
			var correlationID = context.GetCorrelationID();
			return (session, query, headers, extra, correlationID);
		}

		/// <summary>
		/// Gets the params of RequestInfo
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpSettings"></param>
		/// <returns></returns>
		public static (Session Session, Dictionary<string, string> Query, Dictionary<string, string> Headers, Dictionary<string, string> Extra, string CorrelationID) GetRequestInfoParams(this HttpContext context, MCP.Settings mcpSettings)
			=> context.GetRequestInfoParams(mcpSettings?.SystemID);

		static async Task<JToken> ProcessRequestAsync(this RequestInfo requestInfo, bool getSettings, CancellationToken cancellationToken)
		{
			RouterRpcGate.Releaser? ticket = null;
			var stopwatch = Stopwatch.StartNew();
			try
			{
				ticket = await Global.RpcGate.TryEnterAsync(cancellationToken).ConfigureAwait(false);
				if (ticket == null)
				{
					Global.Statistics.RpcRejected();
					throw new SystemBusyException();
				}
				Global.Statistics.RpcEntered();
				using (ticket.Value)
				{
					return getSettings
						? await Router.GetService(requestInfo.ServiceName).GetMcpSettingsAsync(requestInfo, cancellationToken).ConfigureAwait(false)
						: await Router.GetService(requestInfo.ServiceName).ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);
				}
			}
			catch (Exception)
			{
				throw;
			}
			finally
			{
				if (ticket != null)
					Global.Statistics.RpcCompleted(stopwatch);
			}
		}

		static Task<JToken> ProcessRequestAsync(this RequestInfo requestInfo, CancellationToken cancellationToken)
			=> requestInfo.ProcessRequestAsync(false, cancellationToken);

		/// <summary>
		/// Gets MCP settings
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName"></param>
		/// <param name="systemID"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task<MCP.Settings> GetMcpSettingsAsync(this HttpContext context, string serviceName, string systemID, CancellationToken cancellationToken)
		{
			MCP.Settings settings = null;
			try
			{
				var (session, query, headers, extra, correlationID) = context.GetRequestInfoParams(systemID);
				var requestInfo = new RequestInfo(session, serviceName, "MCP", "GET", query, headers, null, extra, correlationID);
				var response = await requestInfo.ProcessRequestAsync(true, cancellationToken).ConfigureAwait(false);
				settings = response.UpdateMcpSettings();
				if (Global.IsDebugLogEnabled || context.ContainsKey("x-logs"))
					await context.WriteLogsAsync("MCP", $"{serviceName} MCP settings{(string.IsNullOrWhiteSpace(systemID) ? "" : $" [{systemID}]")}: {settings?.ToJson()}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("MCP", $"{serviceName} MCP settings error => {ex.Message}", ex, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
			}
			return settings;
		}

		/// <summary>
		/// Gets MCP settings
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task<MCP.Settings> GetMcpSettingsAsync(this HttpContext context, string serviceName, CancellationToken cancellationToken)
			=> context.GetMcpSettingsAsync(serviceName, null, cancellationToken);

		/// <summary>
		/// Updates MCP settings
		/// </summary>
		/// <param name="settings"></param>
		/// <param name="systemID"></param>
		public static MCP.Settings UpdateMcpSettings(this MCP.Settings settings, string systemID = null)
		{
			settings = settings?.Normalize();
			if (settings?.Resources != null && !settings.Resources.IsEmpty)
			{
				var identifier = string.IsNullOrWhiteSpace(systemID) ? "Default" : systemID;
				if (McpHandlerExtensions.Settings.TryGetValue(identifier, out var mcpSettings))
				{
					mcpSettings.SystemID = string.IsNullOrWhiteSpace(systemID) ? null : systemID;
					mcpSettings.AllowAnonymous = settings.AllowAnonymous;
					settings.Resources.ForEach(kvp => mcpSettings.Resources[kvp.Key] = kvp.Value.DeepClone() as JObject);
					settings.Tools?.ForEach(kvp => mcpSettings.Tools[kvp.Key] = kvp.Value.DeepClone() as JObject);
				}
				else
					McpHandlerExtensions.Settings[identifier] = new MCP.Settings
					{
						SystemID = string.IsNullOrWhiteSpace(settings.SystemID) ? null : settings.SystemID,
						AllowAnonymous = settings.AllowAnonymous,
						Resources = new ConcurrentDictionary<string, JObject>(settings.Resources?.Select(kvp => new KeyValuePair<string, JObject>(kvp.Key, kvp.Value.DeepClone() as JObject)), StringComparer.OrdinalIgnoreCase),
						Tools = new ConcurrentDictionary<string, JObject>(settings.Tools?.Select(kvp => new KeyValuePair<string, JObject>(kvp.Key, kvp.Value.DeepClone() as JObject)), StringComparer.OrdinalIgnoreCase)
					};
			}
			return settings;
		}

		/// <summary>
		/// Updates MCP settings
		/// </summary>
		/// <param name="settings"></param>
		/// <returns></returns>
		public static MCP.Settings UpdateMcpSettings(this JToken settings)
			=> new MCP.Settings
			{
				SystemID = settings.Get<string>("SystemID"),
				AllowAnonymous = settings.Get<bool>("AllowAnonymous"),
				Resources = new ConcurrentDictionary<string, JObject>(settings.Get<JObject>("Resources")?.ToDictionary<JObject>()?.Select(kvp => new KeyValuePair<string, JObject>(kvp.Key, kvp.Value.DeepClone() as JObject)), StringComparer.OrdinalIgnoreCase),
				Tools = new ConcurrentDictionary<string, JObject>(settings.Get<JObject>("Tools")?.ToDictionary<JObject>()?.Select(kvp => new KeyValuePair<string, JObject>(kvp.Key, kvp.Value.DeepClone() as JObject)), StringComparer.OrdinalIgnoreCase)
			}.UpdateMcpSettings(settings.Get<string>("SystemID"));

		/// <summary>
		/// Updates MCP settings (from message of API Gateway channel)
		/// </summary>
		/// <param name="message"></param>
		/// <returns></returns>
		public static MCP.Settings UpdateMcpSettings(this CommunicateMessage message)
		{
			if (message.Type.IsEquals("MCP#UpdateSettings"))
				try
				{
					return message.Data.UpdateMcpSettings();
				}
				catch { }
			return null;
		}

		/// <summary>
		/// Gets the MCP protocol version
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpRequest"></param>
		/// <returns></returns>
		/// <exception cref="MCP.InvalidProtocolException"></exception>
		public static string GetMcpProtocolVersion(this HttpContext context, JObject mcpRequest)
		{
			var meta = mcpRequest.Get<JObject>("params")?.Get<JObject>("_meta");
			if (meta == null || meta.Get<JObject>("io.modelcontextprotocol/clientCapabilities") == null)
				throw new MCP.InvalidParamsException("Missing client capabilities");

			var protocolVersion = context.GetHeaderParameter("MCP-Protocol-Version");
			var metaProtocolVersion = meta.Get<string>("io.modelcontextprotocol/protocolVersion");

			if (string.IsNullOrWhiteSpace(protocolVersion))
				throw new MCP.InvalidHeaderException("Missing MCP-Protocol-Version header");

			if (string.IsNullOrWhiteSpace(metaProtocolVersion))
				throw new MCP.InvalidParamsException("Missing protocol version in request meta");

			if (!protocolVersion.IsEquals(metaProtocolVersion))
				throw new MCP.InvalidHeaderException("MCP protocol version mismatch");

			if (!McpHandlerExtensions.SupportedProtocolVersions.Any(version => version == protocolVersion))
				throw new MCP.InvalidProtocolException($"Unsupported MCP protocol version [{protocolVersion}]");

			return protocolVersion;
		}

		/// <summary>
		/// Get the MCP request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task<JObject> GetMcpRequestAsync(this HttpContext context, CancellationToken cancellationToken)
		{
			JObject mcpRequest;
			try
			{
				mcpRequest = context.SetItem("RequestBody", await context.ReadJsonAsync(cancellationToken).ConfigureAwait(false) as JObject) ?? throw new MCP.InvalidBodyException();
			}
			catch (Exception ex)
			{
				throw ex is MCP.InvalidBodyException ? ex : new MCP.MalformedRequestException(ex);
			}

			var jsonrpc = mcpRequest.Get<string>("jsonrpc");
			if (string.IsNullOrWhiteSpace(jsonrpc) || jsonrpc != "2.0")
				throw new MCP.InvalidRequestException("Invalid JSON-RPC version");

			context.GetMcpProtocolVersion(mcpRequest);

			var mcpMethod = context.GetHeaderParameter("MCP-Method");
			if (string.IsNullOrWhiteSpace(mcpMethod))
				throw new MCP.InvalidHeaderException("Missing MCP-Method header");

			if (!mcpMethod.IsEquals(mcpRequest.Get<string>("method")))
				throw new MCP.InvalidHeaderException("MCP header mismatch");

			var mcpName = context.GetHeaderParameter("MCP-Name")?.Decode();
			if (string.IsNullOrWhiteSpace(mcpName))
			{
				if (mcpMethod.IsEquals("tools/call") || mcpMethod.IsEquals("resources/read") || mcpMethod.IsEquals("prompts/get"))
					throw new MCP.InvalidHeaderException("Missing MCP-Name header");
			}
			else if (!mcpName.IsEquals(mcpRequest.Get<JObject>("params")?.Get<string>(mcpMethod.IsEquals("resources/read") ? "uri" : "name")))
				throw new MCP.InvalidHeaderException("MCP header mismatch");

			return mcpRequest;
		}

		/// <summary>
		/// Write the JSON-RPC to MCP client response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="id"></param>
		/// <param name="name"></param>
		/// <param name="json"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteMcpJsonRpcAsync(this HttpContext context, string id, string name, JObject json, CancellationToken cancellationToken)
		{
			var idValue = Int64.TryParse(id, out var idAsNumber) ? new JValue(idAsNumber) : new JValue(id);
			var response = new JObject
			{
				["jsonrpc"] = "2.0",
				["id"] = idValue,
				[name] = json
			};
			if (string.IsNullOrWhiteSpace(id))
				response.Remove("id");

			var headers = new Dictionary<string, string>
			{
				["Cache-Control"] = context.GetHttpCacheControl(true),
				["X-Node"] = Global.NodeID,
				["X-Correlation-ID"] = context.GetCorrelationID()
			};

			return Task.WhenAll
			(
				context.WriteAsync(response.ToBytes(Formatting.None), "application/json", headers, cancellationToken),
				Global.IsDebugLogEnabled || context.ContainsKey("x-logs") ? context.WriteLogsAsync("MCP", $"Response JSON-RPC: {response}") : Task.CompletedTask
			);
		}

		/// <summary>
		/// Write the result to MCP client response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="id"></param>
		/// <param name="result"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteMcpResultAsync(this HttpContext context, string id, JObject result, CancellationToken cancellationToken)
			=> context.WriteMcpJsonRpcAsync(id, "result", result, cancellationToken);

		/// <summary>
		/// Gets the MCP errors
		/// </summary>
		/// <param name="exception"></param>
		/// <returns></returns>
		public static (int Code, string Message, string Type, string Stack) GetMcpErrors(this Exception exception)
		{
			var code = exception.GetHttpStatusCode();
			var message = exception.Message ?? "Unknown error";
			var type = exception.GetTypeName(true) ?? "UnknownException";
			var stack = exception.StackTrace;
			if (exception is WampException wampException)
			{
				var details = wampException.GetDetails();
				code = details.Code;
				message = details.Message;
				type = details.Type;
				stack = details.Stack;
			}
			if (type == "AccessDeniedException")
				message = "Access denied: insufficient permissions";
			return (code, message, type.ToArray("+").Last(), stack);
		}

		/// <summary>
		/// Write the error to MCP client response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="id"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteMcpErrorAsync(this HttpContext context, Exception exception, string id, CancellationToken cancellationToken)
		{
			var code = -32603;
			if (exception is MCP.InvalidHeaderException)
				code = -32020;
			else if (exception is MCP.InvalidProtocolException)
				code = -32022;
			else if (exception is MCP.MalformedRequestException || exception is MCP.InvalidRequestException)
				code = -32600;
			else if (exception is MCP.InvalidBodyException || exception is MCP.InvalidParamsException)
				code = -32602;
			else if (exception is MCP.InvalidMethodException || exception is NotImplementedException)
				code = -32601;
			else if (exception is UnauthorizedException)
				code = -32001;
			else if (exception is AccessDeniedException)
				code = -32003;
			else if (exception is ServiceNotFoundException)
				code = -32004;
			else if (exception is MethodNotAllowedException)
				code = -32005;
			else if (exception is MCP.InvalidCursorException)
				code = -32010;

			var (httpStatus, message, type, stack) = exception.GetMcpErrors();

			if (exception is MCP.InvalidHeaderException || exception is MCP.InvalidProtocolException || exception is MCP.MalformedRequestException || exception is MCP.InvalidCursorException)
				httpStatus = (int)HttpStatusCode.BadRequest;

			else if (exception is MCP.InvalidMethodException || exception is NotImplementedException)
				httpStatus = (int)HttpStatusCode.NotFound;

			else if (exception is UnauthorizedException)
				httpStatus = (int)HttpStatusCode.Unauthorized;

			else if (exception is AccessDeniedException)
				httpStatus = (int)HttpStatusCode.Forbidden;

			else if (exception is ServiceNotFoundException)
				httpStatus = (int)HttpStatusCode.NotFound;

			else if (exception is MethodNotAllowedException)
				httpStatus = (int)HttpStatusCode.MethodNotAllowed;

			var data = new JObject
			{
				["httpStatus"] = httpStatus,
				["type"] = type,
				["stack"] = stack,
				["correlationID"] = context.GetCorrelationID()
			};

			if (exception is MCP.InvalidProtocolException)
			{
				data["supported"] = McpHandlerExtensions.SupportedProtocolVersions.ToJArray();
				data["requested"] = context.GetHeaderParameter("MCP-Protocol-Version");
			}

			var error = new JObject
			{
				["code"] = code,
				["message"] = message,
				["data"] = data
			};

			context.Response.StatusCode = httpStatus;
			return Task.WhenAll
			(
				context.WriteMcpJsonRpcAsync(id, "error", error, cancellationToken),
				context.WriteLogsAsync("MCP", message, exception, Global.ServiceName, LogLevel.Error)
			);
		}

		/// <summary>
		/// Write the error to MCP client response
		/// </summary>
		/// <param name="context"></param>
		/// <param name="id"></param>
		/// <param name="exception"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task WriteMcpErrorAsync(this HttpContext context, string id, Exception exception, CancellationToken cancellationToken)
		{
			var (code, message, type, stack) = exception.GetMcpErrors();
			var result = new JObject
			{
				["resultType"] = "complete",
				["isError"] = true,
				["content"] = new JArray(new JObject
				{
					["type"] = "text",
					["text"] = message
				}),
				["structuredContent"] = new JObject
				{
					["code"] = code,
					["message"] = message,
					["type"] = type,
					["stack"] = stack,
					["correlationID"] = context.GetCorrelationID()
				}
			};
			return Task.WhenAll
			(
				context.WriteMcpResultAsync(id, result, cancellationToken),
				context.WriteLogsAsync("MCP", message, exception, Global.ServiceName, LogLevel.Error)
			);
		}

		/// <summary>
		/// Prepares the opaque cursor the the MCP request
		/// </summary>
		/// <param name="json"></param>
		/// <returns></returns>
		/// <exception cref="MCP.InvalidCursorException"></exception>
		public static JObject PrepareMcpCursor(this JObject json)
		{
			var cursor = json.Get<string>("Cursor") ?? json.Get<string>("cursor");
			if (!string.IsNullOrWhiteSpace(cursor))
				try
				{
					json.Remove(new[] { "Cursor", "cursor" }, _ => json["cursor"] = cursor.FromBase64Url().Decrypt(Global.EncryptionKey).ToBase64Url(true));
				}
				catch (Exception ex)
				{
					throw new MCP.InvalidCursorException(ex);
				}
			else
			{
				cursor = json.Get<string>("NextCursor") ?? json.Get<string>("nextCursor");
				json.Remove(new[] { "NextCursor", "nextCursor" });
				if (!string.IsNullOrWhiteSpace(cursor))
					json["nextCursor"] = cursor.FromBase64Url().Encrypt(Global.EncryptionKey).ToBase64Url(true);
			}
			return json;
		}

		/// <summary>
		/// Process the 'server/discover' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="services"></param>
		/// <param name="instructions"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task ProcessMcpServerDiscoverRequestAsync(this HttpContext context, JObject mcpRequest, JArray services, string instructions, CancellationToken cancellationToken)
		{
			var meta = new JObject
			{
				["io.modelcontextprotocol/serverInfo"] = new JObject
				{
					["name"] = "vieapps-ngx-mcp",
					["version"] = Assembly.GetCallingAssembly().GetVersion(false)
				}
			};
			if (services != null && services.Count > 0)
				meta["net.vieapps/services"] = services;

			var result = new JObject
			{
				["resultType"] = "complete",
				["supportedVersions"] = McpHandlerExtensions.SupportedProtocolVersions.ToJArray(),
				["capabilities"] = new JObject
				{
					["tools"] = new JObject
					{
						["listChanged"] = true
					},
					["resources"] = new JObject
					{
						["listChanged"] = true,
						["subscribe"] = true
					}
				},
				["_meta"] = meta,
				["instructions"] = instructions ?? "Provides access to business services through MCP tools and resources.",
				["ttlMs"] = McpHandlerExtensions.McpTimeToLive,
				["cacheScope"] = "private"
			};

			return context.WriteMcpResultAsync(mcpRequest.Get<string>("id"), result, cancellationToken);
		}

		/// <summary>
		/// Process the 'server/discover' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task ProcessMcpServerDiscoverRequestAsync(this HttpContext context, JObject mcpRequest, CancellationToken cancellationToken)
			=> context.ProcessMcpServerDiscoverRequestAsync(mcpRequest, null, null, cancellationToken);

		/// <summary>
		/// Process the 'resources/templates/list' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpSettings"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task ProcessMcpResourceTemplateListRequestAsync(this HttpContext context, MCP.Settings mcpSettings, JObject mcpRequest, CancellationToken cancellationToken)
		{
			var resources = mcpSettings.Resources?.OrderBy(kvp => kvp.Key).Select(kvp => kvp.Value).ToList() ?? new List<JObject>();
			var resourceTemplates = new JArray();
			var index = mcpRequest.Get<JObject>("params")?.PrepareMcpCursor()?.Get<string>("cursor")?.FromBase64Url()?.ToJson() is JObject cursor ? cursor.Get<int>("Index") : 0;
			var max = index + 20;
			while (index < max && index < resources.Count)
			{
				resourceTemplates.Add(resources[index]);
				index++;
			}

			var result = new JObject
			{
				["resultType"] = "complete",
				["resourceTemplates"] = resourceTemplates,
				["ttlMs"] = McpHandlerExtensions.McpTimeToLive,
				["cacheScope"] = "private"
			};

			if (index < resources.Count)
				result["nextCursor"] = new JObject { ["Index"] = index }.AsString().ToBase64Url();

			return context.WriteMcpResultAsync(mcpRequest.Get<string>("id"), result.PrepareMcpCursor(), cancellationToken);
		}

		/// <summary>
		/// Process the 'resources/list' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpSettings"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static async Task ProcessMcpResourceListRequestAsync(this HttpContext context, MCP.Settings mcpSettings, JObject mcpRequest, CancellationToken cancellationToken)
		{
			var (session, query, headers, extra, correlationID) = context.GetRequestInfoParams(mcpSettings);
			query["object-identity"] = "search";

			var resources = new List<(DateTime LastModified, JObject Json)>();
			await mcpSettings.Resources.ForEachAsync(async mcpResource =>
			{
				try
				{
					var names = mcpResource.Get<string>("name").ToArray(".");
					var serviceName = names[0];
					var objectName = names[1];
					var response = await new RequestInfo(session, serviceName, objectName, "GET", query, headers, null, extra, correlationID).ProcessRequestAsync(cancellationToken).ConfigureAwait(false);
					(response as JArray ?? response?.Get<JArray>("Objects"))?.Select(resource => resource as JObject).ToList().ForEach(resource =>
					{
						var id = resource.Get<string>("ID") ?? resource.Get<string>("Id") ?? resource.Get<string>("id");
						var uri = $"{serviceName}://{objectName}/{id}";
						var name = $"{serviceName}.{objectName}";
						var title = resource.Get<string>("Title") ?? resource.Get<string>("title");
						var description = resource.Get<string>("Description") ?? resource.Get<string>("description") ?? resource.Get<string>("Summary") ?? resource.Get<string>("summary");
						var lastModified = resource.Get<string>("LastModified") ?? resource.Get<string>("lastModified");
						resources.Add((DateTime.Parse(lastModified), new JObject
						{
							["uri"] = uri,
							["name"] = name,
							["title"] = title,
							["description"] = description,
							["mimeType"] = "application/json"
						}));
					});
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("MCP", $"Error occurred while fetching resources => {ex.Message}", ex, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
				}
			}, true, false).ConfigureAwait(false);
			resources = resources.OrderByDescending(info => info.LastModified).ToList();

			var resourcesList = new JArray();
			var index = mcpRequest.Get<JObject>("params")?.PrepareMcpCursor()?.Get<string>("cursor")?.FromBase64Url()?.ToJson() is JObject cursor ? cursor.Get<int>("Index") : 0;
			var max = index + 20;
			while (index < max && index < resources.Count)
			{
				resourcesList.Add(resources[index].Json);
				index++;
			}

			var result = new JObject
			{
				["resultType"] = "complete",
				["resources"] = resourcesList,
				["ttlMs"] = McpHandlerExtensions.McpTimeToLive,
				["cacheScope"] = "private"
			};

			if (index < resources.Count)
				result["nextCursor"] = new JObject { ["Index"] = index }.AsString().ToBase64Url();

			await context.WriteMcpResultAsync(mcpRequest.Get<string>("id"), result.PrepareMcpCursor(), cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Process the 'resources/read' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpSettings"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		/// <exception cref="MCP.InvalidParamsException"></exception>
		public static async Task ProcessMcpResourceReadRequestAsync(this HttpContext context, MCP.Settings mcpSettings, JObject mcpRequest, CancellationToken cancellationToken)
		{
			var requestURI = mcpRequest.Get<JObject>("params")?.Get<string>("uri");
			if (string.IsNullOrWhiteSpace(requestURI))
				throw new MCP.InvalidParamsException();

			if (!Uri.TryCreate(requestURI, UriKind.Absolute, out var uri))
				throw new MCP.InvalidParamsException("Invalid resource URI");

			var serviceName = uri.Scheme;
			var objectName = uri.Host;
			var objectIdentity = uri.AbsolutePath.Trim('/');
			if (string.IsNullOrWhiteSpace(serviceName) || string.IsNullOrWhiteSpace(objectName) || string.IsNullOrWhiteSpace(objectIdentity))
				throw new MCP.InvalidParamsException();

			var (session, query, headers, extra, correlationID) = context.GetRequestInfoParams(mcpSettings);
			query["object-identity"] = objectIdentity;

			try
			{
				var response = await new RequestInfo(session, serviceName, objectName, "GET", query, headers, null, extra, correlationID).ProcessRequestAsync(cancellationToken).ConfigureAwait(false);
				var result = new JObject
				{
					["resultType"] = "complete",
					["contents"] = new JArray(new JObject
					{
						["uri"] = requestURI,
						["mimeType"] = "application/json",
						["text"] = response?.AsString()
					}),
					["ttlMs"] = McpHandlerExtensions.McpTimeToLive,
					["cacheScope"] = "private"
				};
				await context.WriteMcpResultAsync(mcpRequest.Get<string>("id"), result, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteMcpErrorAsync(ex, mcpRequest.Get<string>("id"), cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Process the 'tools/list' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpSettings"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public static Task ProcessMcpToolListRequestAsync(this HttpContext context, MCP.Settings mcpSettings, JObject mcpRequest, CancellationToken cancellationToken)
		{
			var tools = mcpSettings.Tools?.OrderBy(kvp => kvp.Key).Select(kvp => kvp.Value).ToList() ?? new List<JObject>();
			var index = mcpRequest.Get<JObject>("params")?.PrepareMcpCursor()?.Get<string>("cursor")?.FromBase64Url()?.ToJson() is JObject cursor ? cursor.Get<int>("Index") : 0;

			var result = new JObject
			{
				["resultType"] = "complete",
				["tools"] = index < 0 || index >= tools.Count ? new JArray() : tools[index] as JToken,
				["ttlMs"] = McpHandlerExtensions.McpTimeToLive,
				["cacheScope"] = "private"
			};
			if (index >= 0 && index < tools.Count - 1)
				result["nextCursor"] = new JObject { ["Index"] = index + 1 }.AsString().ToBase64Url();

			return context.WriteMcpResultAsync(mcpRequest.Get<string>("id"), result.PrepareMcpCursor(), cancellationToken);
		}

		/// <summary>
		/// Process the 'tools/call' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpSettings"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		/// <exception cref="MCP.InvalidParamsException"></exception>
		public static async Task ProcessMcpToolCallRequestAsync(this HttpContext context, MCP.Settings mcpSettings, JObject mcpRequest, CancellationToken cancellationToken)
		{
			var names = context.GetHeaderParameter("MCP-Name")?.Decode()?.ToArray(".", true);
			var serviceName = names.Length > 0 ? names[0] : null;
			var objectName = names.Length > 1 ? names[1] : null;
			var verb = names.Length > 2 ? names[2] : null;
			if (string.IsNullOrWhiteSpace(serviceName) || string.IsNullOrWhiteSpace(objectName) || string.IsNullOrWhiteSpace(verb))
				throw new MCP.InvalidParamsException();

			var body = mcpRequest.Get<JObject>("params")?.Get<JObject>("arguments")?.PrepareMcpCursor() ?? throw new MCP.InvalidParamsException();
			var (session, query, headers, extra, correlationID) = context.GetRequestInfoParams(mcpSettings);
			if (verb.IsEquals("search"))
				query["object-identity"] = "search";
			else if (!verb.IsEquals("create"))
				query["object-identity"] = body.Get<string>("ID");

			try
			{
				var response = await new RequestInfo(session, serviceName, objectName, verb.ToUpper(), query, headers, body.AsString(), extra, correlationID).ProcessRequestAsync(cancellationToken).ConfigureAwait(false) as JObject;
				var result = new JObject
				{
					["resultType"] = "complete",
					["structuredContent"] = response?.PrepareMcpCursor(),
					["content"] = new JArray(new JObject
					{
						["type"] = "text",
						["text"] = response?.AsString()
					}),
					["isError"] = false,
				};
				await context.WriteMcpResultAsync(mcpRequest.Get<string>("id"), result, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteMcpErrorAsync(mcpRequest.Get<string>("id"), ex, cancellationToken).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Process the 'subscriptions/listen' request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="mcpRequest"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		/// <exception cref="MCP.InvalidRequestException"></exception>
		public static async Task ProcessMcpSubscriptionListenRequestAsync(this HttpContext context, JObject mcpRequest, CancellationToken cancellationToken)
		{
			if (!context.IsEventStreamRequest())
				throw new MCP.InvalidHeaderException("MCP header mismatch");

			var subscriptionID = mcpRequest.Get<string>("id");
			if (string.IsNullOrWhiteSpace(subscriptionID))
				throw new MCP.InvalidRequestException();

			var notifications = mcpRequest.Get<JObject>("params")?.Get<JObject>("notifications") ?? new JObject();

			var toolsListChanged = notifications.Get<bool>("toolsListChanged");
			var resourcesListChanged = notifications.Get<bool>("resourcesListChanged");
			var resourceURIs = new HashSet<string>(notifications.Get<JArray>("resourceSubscriptions")?.Select(uri => uri?.ToString()).Where(uri => !string.IsNullOrWhiteSpace(uri)) ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

			while (Router.IncomingChannel == null)
				await Task.Delay(UtilityService.GetRandomNumber(123, 456), cancellationToken).ConfigureAwait(false);

			await context.InitializeEventStreamAsync().ConfigureAwait(false);

			var idValue = Int64.TryParse(subscriptionID, out var idAsNumber) ? new JValue(idAsNumber) : new JValue(subscriptionID);

			JObject getNotification(string method, JObject parameters = null)
			{
				parameters = parameters ?? new JObject();
				parameters["_meta"] = new JObject
				{
					["io.modelcontextprotocol/subscriptionId"] = idValue.DeepClone()
				};
				return new JObject
				{
					["jsonrpc"] = "2.0",
					["method"] = method,
					["params"] = parameters
				};
			}

			var honored = new JObject();
			if (toolsListChanged)
				honored["toolsListChanged"] = true;
			if (resourcesListChanged)
				honored["resourcesListChanged"] = true;
			if (resourceURIs.Count > 0)
				honored["resourceSubscriptions"] = resourceURIs.ToJArray();

			await context.PushEventMessageAsync(getNotification("notifications/subscriptions/acknowledged", new JObject { ["notifications"] = honored }).AsString()).ConfigureAwait(false);

			var communicator = Router.IncomingChannel.Subscribe<CommunicateMessage>
			(
				"messages.services.mcp",
				message =>
				{
					if (message.Type.IsEquals("tools/changed") && toolsListChanged)
						return context.PushEventMessageAsync(getNotification("notifications/tools/list_changed").AsString());
					if (message.Type.IsEquals("resources/created") && resourcesListChanged)
						return context.PushEventMessageAsync(getNotification("notifications/resources/list_changed").AsString());
					if (message.Type.IsEquals("resources/updated"))
					{
						var uri = message.Data?.Get<string>("URI");
						if (!string.IsNullOrWhiteSpace(uri) && resourceURIs.Contains(uri))
							return context.PushEventMessageAsync(getNotification("notifications/resources/updated", new JObject { ["uri"] = uri }).AsString());
					}
					return Task.CompletedTask;
				},
				exception => context.WriteLogsAsync("MCP", $"Communicating error => {exception.Message}", exception, Global.ServiceName, LogLevel.Error)
			);

			try
			{
				while (!cancellationToken.IsCancellationRequested)
					await Task.Delay(UtilityService.GetRandomNumber(123, 456), cancellationToken).ConfigureAwait(false);
			}
			catch { }
			finally
			{
				communicator?.Dispose();
			}
		}

		/// <summary>
		/// Process the request of MCP client
		/// </summary>
		/// <param name="context"></param>
		/// <param name="getIdentifyJsonAsync"></param>
		/// <returns></returns>
		public static async Task ProcessMcpRequestAsync(this HttpContext context, Func<HttpContext, CancellationToken, Task<JObject>> getIdentifyJsonAsync = null)
		{
			if (!context.Request.Method.IsEquals("POST"))
				throw new MethodNotAllowedException();

			var stopwatch = Stopwatch.StartNew();
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted))
				try
				{
					// prepare
					var mcpRequest = await context.GetMcpRequestAsync(cts.Token).ConfigureAwait(false);
					var mcpMethod = context.GetHeaderParameter("MCP-Method");
					MCP.Settings mcpSettings = null;

					// identify the system
					JObject identifyJson = null;
					if (getIdentifyJsonAsync != null)
						identifyJson = await getIdentifyJsonAsync(context, cts.Token).ConfigureAwait(false);

					var systemID = identifyJson?.Get<string>("ID");
					var systemTitle = identifyJson?.Get<string>("Title");
					var serviceNames = UtilityService.GetAppSetting("MCP:Services", Global.ServiceName).ToArray(";", true);

					// get settings
					if (string.IsNullOrWhiteSpace(systemID))
					{
						if (!McpHandlerExtensions.Settings.TryGetValue("Default", out mcpSettings))
							await serviceNames.ForEachAsync(serviceName => context.GetMcpSettingsAsync(serviceName, cts.Token), true, false).ConfigureAwait(false);
						McpHandlerExtensions.Settings.TryGetValue("Default", out mcpSettings);
					}
					else if (!McpHandlerExtensions.Settings.TryGetValue(systemID, out mcpSettings))
						mcpSettings = await context.GetMcpSettingsAsync(Global.ServiceName, systemID, cts.Token).ConfigureAwait(false);

					if (mcpSettings == null)
						throw new ServiceNotFoundException("Unavailable");

					if (!mcpSettings.AllowAnonymous && !context.IsAuthenticated())
						throw new UnauthorizedException("Unauthorized: missing or invalid credentials");

					// process the request
					await context.WriteLogsAsync("MCP", $"Start process request{(Global.IsDebugLogEnabled || context.ContainsKey("x-logs") ? $"\r\nRequest JSON-RPC: {mcpRequest}" : "")}").ConfigureAwait(false);

					if (mcpMethod.IsEquals("tools/call"))
						await context.ProcessMcpToolCallRequestAsync(mcpSettings, mcpRequest, cts.Token).ConfigureAwait(false);

					else if (mcpMethod.IsEquals("tools/list"))
						await context.ProcessMcpToolListRequestAsync(mcpSettings, mcpRequest, cts.Token).ConfigureAwait(false);

					else if (mcpMethod.IsEquals("resources/templates/list"))
						await context.ProcessMcpResourceTemplateListRequestAsync(mcpSettings, mcpRequest, cts.Token).ConfigureAwait(false);

					else if (mcpMethod.IsEquals("resources/list"))
						await context.ProcessMcpResourceListRequestAsync(mcpSettings, mcpRequest, cts.Token).ConfigureAwait(false);

					else if (mcpMethod.IsEquals("resources/read"))
						await context.ProcessMcpResourceReadRequestAsync(mcpSettings, mcpRequest, cts.Token).ConfigureAwait(false);

					else if (mcpMethod.IsEquals("subscriptions/listen"))
						await context.ProcessMcpSubscriptionListenRequestAsync(mcpRequest, cts.Token).ConfigureAwait(false);

					else if (mcpMethod.IsEquals("server/discover"))
					{
						var	services = string.IsNullOrWhiteSpace(mcpSettings.SystemID) ? serviceNames.Select(serviceName => new JObject { ["name"] = serviceName.ToLower(), ["title"] = serviceName }).ToJArray() : null;
						var instructions = string.IsNullOrWhiteSpace(mcpSettings.SystemID) ? null : $"Provides access to the {Global.ServiceName} service{(string.IsNullOrWhiteSpace(systemTitle) ? "" : $" of {systemTitle}")} through MCP tools and resources.";
						await context.ProcessMcpServerDiscoverRequestAsync(mcpRequest, services, instructions, cts.Token).ConfigureAwait(false);
					}

					else
						throw new NotImplementedException();
				}
				catch (OperationCanceledException) { }
				catch (Exception ex)
				{
					await context.WriteMcpErrorAsync(ex, context.GetItem<JObject>("RequestBody")?.Get<string>("id"), cts.Token).ConfigureAwait(false);
				}
				finally
				{
					await context.WriteLogsAsync("MCP", $"End process request - Execution times: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);
				}
		}
	}
}