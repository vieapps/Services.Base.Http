#region Related components
using System;
using System.Threading.Tasks;

using WampSharp.Core.Listener;
using WampSharp.V2;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{

		#region Properties
		static IWampChannel _IncommingChannel = null, _OutgoingChannel = null;
		static long _IncommingChannelSessionID = 0, _OutgoingChannelSessionID = 0;
		static bool _ChannelsAreClosedBySystem = false;

		/// <summary>
		/// Gets the incomming channel of the WAMP router
		/// </summary>
		public static IWampChannel IncommingChannel
		{
			get
			{
				return Global._IncommingChannel;
			}
		}

		/// <summary>
		/// Gets the session's identity of the incomming channel of the WAMP router
		/// </summary>
		public static long IncommingChannelSessionID
		{
			get
			{
				return Global._IncommingChannelSessionID;
			}
		}

		/// <summary>
		/// Gets the outgoing channel of the WAMP router
		/// </summary>
		public static IWampChannel OutgoingChannel
		{
			get
			{
				return Global._OutgoingChannel;
			}
		}

		/// <summary>
		/// Gets the session's identity of the outgoing channel of the WAMP router
		/// </summary>
		public static long OutgoingChannelSessionID
		{
			get
			{
				return Global._OutgoingChannelSessionID;
			}
		}

		/// <summary>
		/// Gets the state that determines that the WAMP channels are closed by the system
		/// </summary>
		public static bool ChannelsAreClosedBySystem
		{
			get
			{
				return Global._ChannelsAreClosedBySystem;
			}
		}
		#endregion

		static Tuple<string, string, bool> GetLocationInfo()
		{
			var address = UtilityService.GetAppSetting("RouterAddress", "ws://127.0.0.1:16429/");
			var realm = UtilityService.GetAppSetting("RouterRealm", "VIEAppsRealm");
			var mode = UtilityService.GetAppSetting("RouterChannelsMode", "MsgPack");
			return new Tuple<string, string, bool>(address, realm, mode.IsEquals("json"));
		}

		/// <summary>
		/// Opens the incomming channel of the WAMP router
		/// </summary>
		/// <param name="onConnectionEstablished"></param>
		/// <param name="onConnectionBroken"></param>
		/// <param name="onConnectionError"></param>
		/// <returns></returns>
		public static async Task OpenIncomingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global._IncommingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global._IncommingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			Global._IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, arguments) =>
			{
				Global._IncommingChannelSessionID = arguments.SessionId;
				Global.WriteLogs($"The incoming connection is established - Session ID: {arguments.SessionId}");
			};

			if (onConnectionEstablished != null)
				Global._IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global._IncommingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global._IncommingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global._IncommingChannel.Open().ConfigureAwait(false);
		}

		/// <summary>
		/// Closes the incomming channel of the WAMP router
		/// </summary>
		/// <param name="message">The message to send to WAMP router before closing the channel</param>
		public static void CloseIncomingChannel(string message = null)
		{
			if (Global._IncommingChannel != null)
			{
				Global._IncommingChannel.Close(message ?? "The incoming channel is closed", new GoodbyeDetails());
				Global._IncommingChannel = null;
				Global._IncommingChannelSessionID = 0;
			}
		}

		/// <summary>
		/// Opens the outgoging channel of the WAMP router
		/// </summary>
		/// <param name="onConnectionEstablished"></param>
		/// <param name="onConnectionBroken"></param>
		/// <param name="onConnectionError"></param>
		/// <returns></returns>
		public static async Task OpenOutgoingChannelAsync(Action<object, WampSessionCreatedEventArgs> onConnectionEstablished = null, Action<object, WampSessionCloseEventArgs> onConnectionBroken = null, Action<object, WampConnectionErrorEventArgs> onConnectionError = null)
		{
			if (Global._OutgoingChannel != null)
				return;

			var info = Global.GetLocationInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global._OutgoingChannel = useJsonChannel
				? (new DefaultWampChannelFactory()).CreateJsonChannel(address, realm)
				: (new DefaultWampChannelFactory()).CreateMsgpackChannel(address, realm);

			Global._OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, arguments) =>
			{
				Global._OutgoingChannelSessionID = arguments.SessionId;
				Global.WriteLogs($"The outgoing connection is established - Session ID: {arguments.SessionId}");
			};

			if (onConnectionEstablished != null)
				Global._OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += new EventHandler<WampSessionCreatedEventArgs>(onConnectionEstablished);

			if (onConnectionBroken != null)
				Global._OutgoingChannel.RealmProxy.Monitor.ConnectionBroken += new EventHandler<WampSessionCloseEventArgs>(onConnectionBroken);

			if (onConnectionError != null)
				Global._OutgoingChannel.RealmProxy.Monitor.ConnectionError += new EventHandler<WampConnectionErrorEventArgs>(onConnectionError);

			await Global._OutgoingChannel.Open().ConfigureAwait(false);
		}

		/// <summary>
		/// Closes the outgoing channel of the WAMP router
		/// </summary>
		/// <param name="message">The message to send to WAMP router before closing the channel</param>
		public static void CloseOutgoingChannel(string message = null)
		{
			if (Global._OutgoingChannel != null)
			{
				Global._OutgoingChannel.Close(message ?? "The outgoing channel is closed", new GoodbyeDetails());
				Global._OutgoingChannel = null;
				Global._OutgoingChannelSessionID = 0;
			}
		}

		/// <summary>
		/// Opens the WAMP channels with default settings
		/// </summary>
		/// <param name="onIncommingConnectionEstablished"></param>
		/// <param name="onOutgoingConnectionEstablished"></param>
		/// <returns></returns>
		public static async Task OpenChannelsAsync(Action<object, WampSessionCreatedEventArgs> onIncommingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null)
		{
			await Global.OpenIncomingChannelAsync(
				onIncommingConnectionEstablished,
				(sender, args) => {
					if (args.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs($"The incoming connection is broken because the router is not found or the router is refused - Session ID: {args.SessionId}\r\n- Reason: {(string.IsNullOrWhiteSpace(args.Reason) ? "Unknown" : args.Reason)} - {args.CloseType}");
					else if (Global._IncommingChannel != null)
						(new WampChannelReconnector(Global._IncommingChannel, async () =>
						{
							await Task.Delay(123).ConfigureAwait(false);
							try
							{
								await Global._IncommingChannel.Open().ConfigureAwait(false);
								Global.WriteLogs("Re-connect the incoming connection successful");
							}
							catch (Exception ex)
							{
								Global.WriteLogs("Error occurred while re-connecting the incoming connection", ex);
							}
						})).Start();
				},
				(sender, args) => {
					Global.WriteLogs($"Got an error of incoming connection: {(args.Exception != null ? args.Exception.Message : "None")}", args.Exception);
				}
			).ConfigureAwait(false);

			await Global.OpenOutgoingChannelAsync(
				onOutgoingConnectionEstablished,
				(sender, args) => {
					if (args.CloseType.Equals(SessionCloseType.Disconnection))
						Global.WriteLogs($"The outgoing connection is broken because the router is not found or the router is refused - Session ID: {args.SessionId}\r\n- Reason: {(string.IsNullOrWhiteSpace(args.Reason) ? "Unknown" : args.Reason)} - {args.CloseType}");
					else if (Global._OutgoingChannel != null)
						(new WampChannelReconnector(Global._OutgoingChannel, async () =>
						{
							await Task.Delay(234).ConfigureAwait(false);
							try
							{
								await Global._OutgoingChannel.Open().ConfigureAwait(false);
								Global.WriteLogs("Re-connect the outgoing connection successful");
							}
							catch (Exception ex)
							{
								Global.WriteLogs("Error occurred while re-connecting the outgoing connection", ex);
							}
						})).Start();
				},
				(sender, args) => {
					Global.WriteLogs($"Got an error of outgoing connection: {(args.Exception != null ? args.Exception.Message : "None")}", args.Exception);
				}
			).ConfigureAwait(false);
		}

		/// <summary>
		/// Closes all WAMP channels
		/// </summary>
		public static void CloseChannels()
		{
			Global._ChannelsAreClosedBySystem = true;
			Global.CloseIncomingChannel();
			Global.CloseOutgoingChannel();
		}
	}
}