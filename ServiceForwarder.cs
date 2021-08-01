using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;

namespace net.vieapps.Services
{
	/// <summary>
	/// Forwards a request to a remote HTTP service in the VIEApps NGX API Gateway
	/// </summary>
	public class ServiceForwarder
	{
		/// <summary>
		/// Prepares the request before sending
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="endpointURL"></param>
		/// <param name="dataSource"></param>
		/// <param name="cancellationToken"></param>
		/// <returns>The string that presents the well-formed URL of the remote end-point</returns>
		public virtual Task<string> PrepareAsync(RequestInfo requestInfo, string endpointURL, string dataSource, CancellationToken cancellationToken)
		{
			var url = endpointURL ?? "/";
			var objectName = requestInfo.Query["object-name"];
			if (!string.IsNullOrWhiteSpace(objectName))
			{
				var objectIdentity = requestInfo.GetObjectIdentity();
				url += $"{(url.EndsWith("/") ? "" : "/")}{objectName}{(string.IsNullOrWhiteSpace(objectIdentity) ? "" : $"/{objectIdentity}")}";
			}
			var query = requestInfo.Query.Where(kvp => !kvp.Key.IsEquals("service-name") && !kvp.Key.IsEquals("object-name") && !kvp.Key.IsEquals("object-identity")).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
			url += query.Any() ? $"{(url.IndexOf("?") > 0 ? "&" : "?")}{query.ToString("&", kvp => $"{kvp.Key}={kvp.Value?.UrlEncode()}")}" : "";
			return Task.FromResult(url);
		}

		/// <summary>
		/// Normalizes the body before response to client
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="body"></param>
		/// <param name="cancellationToken"></param>
		/// <returns>The normalized JSON</returns>
		public virtual Task<JToken> NormalizeAsync(RequestInfo requestInfo, JToken body, CancellationToken cancellationToken)
			=> Task.FromResult(body);
	}
}