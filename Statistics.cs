using System.Threading;
using System.Diagnostics;
namespace net.vieapps.Services
{
	public sealed class Statistics
	{
		long _requestsTotal;
		int _requestsInFlight;
		long _cacheL1Hit304;
		long _cacheL1Hit200;
		long _cacheL1Miss;
		long _cacheL2Hit304;
		long _cacheL2Hit200;
		long _cacheL2Miss;
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
			=> Interlocked.Increment(ref this._cacheL1Hit304);

		public long L1Hit200()
			=> Interlocked.Increment(ref this._cacheL1Hit200);

		public long L1Hit(bool is304)
			=> is304 ? this.L1Hit304() : this.L1Hit200();

		public long CacheL1Hit304Count => Volatile.Read(ref this._cacheL1Hit304);

		public long CacheL1Hit200Count => Volatile.Read(ref this._cacheL1Hit200);

		public long CacheL1HitCount => this.CacheL1Hit304Count + this.CacheL1Hit200Count;

		public long L1Miss()
			=> Interlocked.Increment(ref this._cacheL1Miss);

		public long CacheL1MissCount => Volatile.Read(ref this._cacheL1Miss);

		public long L2Hit304()
			=> Interlocked.Increment(ref this._cacheL2Hit304);

		public long L2Hit200()
			=> Interlocked.Increment(ref this._cacheL2Hit200);

		public long L2Hit(bool is304)
			=> is304 ? this.L2Hit304() : this.L2Hit200();

		public long CacheL2Hit304Count => Volatile.Read(ref this._cacheL2Hit304);

		public long CacheL2Hit200Count => Volatile.Read(ref this._cacheL2Hit200);

		public long CacheL2HitCount => this.CacheL2Hit304Count + this.CacheL2Hit200Count;

		public long L2Miss()
			=> Interlocked.Increment(ref this._cacheL2Miss);

		public long CacheL2MissCount => Volatile.Read(ref this._cacheL2Miss);

		public double GetCacheL1HitRatio()
			=> this.RequestsTotal > 0
				? this.CacheL1HitCount * 100.0 / this.RequestsTotal
				: 0;

		public double GetCacheL2HitRatio(bool useL1Cache)
			=> useL1Cache
				? this.CacheL1MissCount > 0
					? this.CacheL2HitCount * 100.0 / this.CacheL1MissCount
					: 0
				: this.RequestsTotal > 0
					? this.CacheL2HitCount * 100.0 / this.RequestsTotal
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

			long currentMax;
			do
			{
				currentMax = Volatile.Read(ref this._rpcMaxLatency);
				if (elapsedMilliseconds <= currentMax)
					return;
			}
			while (Interlocked.CompareExchange(ref this._rpcMaxLatency, elapsedMilliseconds, currentMax) != currentMax);
		}

		public void RpcCompleted(Stopwatch stopwatch)
			=> this.RpcCompleted(stopwatch.ElapsedMilliseconds);

		public long RpcMaxLatency => Volatile.Read(ref this._rpcMaxLatency);

		public double RpcAverageLatency
		{
			get
			{
				var count = Volatile.Read(ref this._rpcCompleted);
				return count <= 0 ? 0 : (double)Volatile.Read(ref this._rpcLatencyTotal) / count;
			}
		}

		public double GetRpcEnteredRate(double elapsedSeconds)
			=> Statistics.GetRate(ref this._lastRpcEntered, this.RpcEnteredCount, elapsedSeconds);

		public double GetRpcCompletedRate(double elapsedSeconds)
			=> Statistics.GetRate(ref this._lastRpcCompleted, this._rpcCompleted, elapsedSeconds);
	}
}