using System.Threading;
using System.Diagnostics;
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
		long _rpcCompleted;
		long _rpcLatencyTotal;
		long _rpcMaxLatency;
		long _lastRequestsTotal;
		long _lastRpcEntered;
		long _lastRpcCompleted;

		static double GetRate(ref long last, long current, double elapsed)
		{
			if (elapsed <= 0)
				return 0;

			var delta = current - Interlocked.Exchange(ref last, current);
			return delta > 0 ? delta / elapsed : 0;
		}

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

		public double GetRequestsRate(double elapsedSeconds)
				=> Statistics.GetRate(ref this._lastRequestsTotal, this.RequestsTotal, elapsedSeconds);

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

		public double GetL1HitRatio()
			=> this.RequestsTotal > 0
				? this.L1HitCount * 100.0 / this.RequestsTotal
				: 0;

		public double GetL2HitRatio(bool useL1Cache)
			=> useL1Cache
				? this.L1MissCount > 0
					? this.L2HitCount * 100.0 / this.L1MissCount
					: 0
				: this.RequestsTotal > 0
					? this.L2HitCount * 100.0 / this.RequestsTotal
					: 0;

		public void RpcEntered()
		{
			Interlocked.Increment(ref this._rpcEntered);
			Interlocked.Increment(ref this._rpcInFlight);
		}

		public long RpcEnteredCount => Volatile.Read(ref this._rpcEntered);

		public int RpcInFlightCount => Volatile.Read(ref this._rpcInFlight);

		public long RpcRejectedCount => Volatile.Read(ref this._rpcRejected);

		public void RpcRejected()
			=> Interlocked.Increment(ref this._rpcRejected);

		public long RpcCompletedCount => Volatile.Read(ref this._rpcCompleted);

		public void RpcCompleted(long elapsedMilliseconds)
		{
			if (Interlocked.Decrement(ref this._rpcInFlight) < 0)
				Interlocked.Exchange(ref this._rpcInFlight, 0);
			Interlocked.Add(ref this._rpcLatencyTotal, elapsedMilliseconds);
			Interlocked.Increment(ref this._rpcCompleted);
			this.UpdateMaxLatency(elapsedMilliseconds);
		}

		public void RpcCompleted(Stopwatch stopwatch)
			=> this.RpcCompleted(stopwatch.ElapsedMilliseconds);

		public double GetRpcEnteredRate(double elapsedSeconds)
				=> Statistics.GetRate(ref this._lastRpcEntered, this.RpcEnteredCount, elapsedSeconds);

		public double GetRpcCompletedRate(double elapsedSeconds)
			=> Statistics.GetRate(ref this._lastRpcCompleted, this._rpcCompleted, elapsedSeconds);

		void UpdateMaxLatency(long elapsedMilliseconds)
		{
			long currentMax;
			do
			{
				currentMax = Volatile.Read(ref this._rpcMaxLatency);
				if (elapsedMilliseconds <= currentMax)
					return;
			}
			while (Interlocked.CompareExchange(ref this._rpcMaxLatency, elapsedMilliseconds, currentMax) != currentMax);
		}

		public long RpcMaxLatency => Volatile.Read(ref this._rpcMaxLatency);

		public double RpcAvgLatency
		{
			get
			{
				var count = Volatile.Read(ref this._rpcCompleted);
				return count <= 0 ? 0 : (double)Volatile.Read(ref this._rpcLatencyTotal) / count;
			}
		}
	}
}