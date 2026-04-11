using System.Threading;
namespace net.vieapps.Services
{
	public sealed class Statistics
	{
		long _requestsTotal;
		int _requestsInFlight;
		long _l1Hit304;
		long _l1Hit200;
		long _l1Miss;
		long _l2Hit304;
		long _l2Hit200;
		long _l2Miss;
		long _rpcEntered;
		int _rpcInFlight;
		long _rpcRejected;
		long _lastRequestsTotal;
		long _lastRpcEntered;

		public void IncreaseRequest()
		{
			Interlocked.Increment(ref this._requestsTotal);
			Interlocked.Increment(ref this._requestsInFlight);
		}

		public void DecreaseRequest()
		{
			if (Interlocked.Decrement(ref this._requestsInFlight) < 0)
				Interlocked.Exchange(ref this._requestsInFlight, 0);
		}

		public long RequestsTotal => Volatile.Read(ref this._requestsTotal);

		public int RequestsInFlight => Volatile.Read(ref this._requestsInFlight);

		public long L1Hit304()
			=> Interlocked.Increment(ref this._l1Hit304);

		public long L1Hit200()
			=> Interlocked.Increment(ref this._l1Hit200);

		public long L1Hit(bool is304)
			=> is304 ? this.L1Hit304() : this.L1Hit200();

		public long L1Hit304Count => Volatile.Read(ref this._l1Hit304);

		public long L1Hit200Count => Volatile.Read(ref this._l1Hit200);

		public long L1HitCount
		{
			get
			{
				var hit304 = Volatile.Read(ref this._l1Hit304);
				var hit200 = Volatile.Read(ref this._l1Hit200);
				return hit304 + hit200;
			}
		}

		public long L1Miss()
			=> Interlocked.Increment(ref this._l1Miss);

		public long L1MissCount => Volatile.Read(ref this._l1Miss);

		public long L2Hit304()
			=> Interlocked.Increment(ref this._l2Hit304);

		public long L2Hit200()
			=> Interlocked.Increment(ref this._l2Hit200);

		public long L2Hit(bool is304)
			=> is304 ? this.L2Hit304() : this.L2Hit200();

		public long L2Hit304Count => Volatile.Read(ref this._l2Hit304);

		public long L2Hit200Count => Volatile.Read(ref this._l2Hit200);

		public long L2HitCount
		{
			get
			{
				var hit304 = Volatile.Read(ref this._l2Hit304);
				var hit200 = Volatile.Read(ref this._l2Hit200);
				return hit304 + hit200;
			}
		}

		public long L2Miss()
			=> Interlocked.Increment(ref this._l2Miss);

		public long L2MissCount => Volatile.Read(ref this._l2Miss);

		public void RpcEntered()
		{
			Interlocked.Increment(ref this._rpcEntered);
			Interlocked.Increment(ref this._rpcInFlight);
		}

		public long RpcEnteredCount => Volatile.Read(ref this._rpcEntered);

		public void RpcCompleted()
		{
			if (Interlocked.Decrement(ref this._rpcInFlight) < 0)
				Interlocked.Exchange(ref this._rpcInFlight, 0);
		}

		public int RpcInFlightCount => Volatile.Read(ref this._rpcInFlight);

		public void RpcRejected()
			=> Interlocked.Increment(ref this._rpcRejected);

		public long RpcRejectedCount => Volatile.Read(ref this._rpcRejected);

		public double GetL1HitRate()
			=> this.RequestsTotal > 0
				? this.L1HitCount * 100.0 / this.RequestsTotal
				: 0;

		public double GetL2HitRate(bool hasL1Cache)
			=> hasL1Cache
				? this.L1MissCount > 0
					? this.L2HitCount * 100.0 / this.L1MissCount
					: 0
				: this.RequestsTotal > 0
					? this.L2HitCount * 100.0 / this.RequestsTotal
					: 0;

		public double GetRequestsRate(double elapsedSeconds)
				=> Statistics.GetRate(ref this._lastRequestsTotal, this.RequestsTotal, elapsedSeconds);

		public double GetRpcRate(double elapsedSeconds)
				=> Statistics.GetRate(ref this._lastRpcEntered, this.RpcEnteredCount, elapsedSeconds);

		static double GetRate(ref long last, long current, double elapsed)
		{
			if (elapsed <= 0)
				return 0;

			var delta = current - Interlocked.Exchange(ref last, current);
			return delta > 0 ? delta / elapsed : 0;
		}
	}
}