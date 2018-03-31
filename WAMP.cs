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

		/// <summary>
		/// Gets information of WAMP router
		/// </summary>
		/// <returns></returns>
		public static Tuple<string, string, bool> GetRouterInfo()
		{
			return new Tuple<string, string, bool>(
				UtilityService.GetAppSetting("Router:Address", "ws://127.0.0.1:16429/"),
				UtilityService.GetAppSetting("Router:Realm", "VIEAppsRealm"),
				"json".IsEquals(UtilityService.GetAppSetting("Router:ChannelsMode", "MsgPack"))
			);
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

			var info = Global.GetRouterInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global._IncommingChannel = useJsonChannel
				? new DefaultWampChannelFactory().CreateJsonChannel(address, realm)
				: new DefaultWampChannelFactory().CreateMsgpackChannel(address, realm);

			Global._IncommingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, args) =>
			{
				Global._IncommingChannelSessionID = args.SessionId;
				Global.WriteLogs($"The incoming connection is established - Session ID: {args.SessionId}");
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
				try
				{
					Global._IncommingChannel.Close(message ?? "The incoming channel is closed", new GoodbyeDetails());
					Global._IncommingChannel = null;
					Global._IncommingChannelSessionID = 0;
				}
				catch { }
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

			var info = Global.GetRouterInfo();
			var address = info.Item1;
			var realm = info.Item2;
			var useJsonChannel = info.Item3;

			Global._OutgoingChannel = useJsonChannel
				? new DefaultWampChannelFactory().CreateJsonChannel(address, realm)
				: new DefaultWampChannelFactory().CreateMsgpackChannel(address, realm);

			Global._OutgoingChannel.RealmProxy.Monitor.ConnectionEstablished += (sender, args) =>
			{
				Global._OutgoingChannelSessionID = args.SessionId;
				Global.WriteLogs($"The outgoing connection is established - Session ID: {args.SessionId}");
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
				try
				{
					Global._OutgoingChannel.Close(message ?? "The outgoing channel is closed", new GoodbyeDetails());
					Global._OutgoingChannel = null;
					Global._OutgoingChannelSessionID = 0;
				}
				catch { }
		}

		/// <summary>
		/// Opens the WAMP channels with default settings
		/// </summary>
		/// <param name="onIncommingConnectionEstablished"></param>
		/// <param name="onOutgoingConnectionEstablished"></param>
		/// <returns></returns>
		public static async Task OpenChannelsAsync(Action<object, WampSessionCreatedEventArgs> onIncommingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null)
		{
			await Task.WhenAll(
				Global.OpenIncomingChannelAsync(
					onIncommingConnectionEstablished,
					(sender, args) => {
						if (!Global._ChannelsAreClosedBySystem && !args.CloseType.Equals(SessionCloseType.Disconnection) && Global._IncommingChannel != null)
							try
							{
								new WampChannelReconnector(Global._IncommingChannel, async () =>
								{
									try
									{
										await Task.Delay(123).ConfigureAwait(false);
										await Global._IncommingChannel.Open().ConfigureAwait(false);
										await Global.WriteLogsAsync("Re-connect the incoming connection successful").ConfigureAwait(false);
									}
									catch (Exception ex)
									{
										await Global.WriteLogsAsync("Error occurred while re-connecting the incoming connection", ex).ConfigureAwait(false);
									}
								}).Start();
							}
							catch { }
					},
					(sender, args) => {
						Global.WriteLogs($"Got an error of incoming connection: {(args.Exception != null ? args.Exception.Message : "None")}", args.Exception);
					}
				),
				Global.OpenOutgoingChannelAsync(
					onOutgoingConnectionEstablished,
					(sender, args) => {
						if (!Global._ChannelsAreClosedBySystem && !args.CloseType.Equals(SessionCloseType.Disconnection) && Global._OutgoingChannel != null)
							try
							{
								new WampChannelReconnector(Global._OutgoingChannel, async () =>
								{
									try
									{
										await Task.Delay(234).ConfigureAwait(false);
										await Global._OutgoingChannel.Open().ConfigureAwait(false);
										await Global.WriteLogsAsync("Re-connect the outgoing connection successful").ConfigureAwait(false);
									}
									catch (Exception ex)
									{
										await Global.WriteLogsAsync("Error occurred while re-connecting the outgoing connection", ex).ConfigureAwait(false);
									}
								}).Start();
							}
							catch { }
					},
					(sender, args) => {
						Global.WriteLogs($"Got an error of outgoing connection: {(args.Exception != null ? args.Exception.Message : "None")}", args.Exception);
					}
				)
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