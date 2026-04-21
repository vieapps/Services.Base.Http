using System.Threading;
using System.Diagnostics;
namespace net.vieapps.Services
{
	public sealed class Statistics
	{
		long _requestsTotal;
		int _requestsInFlight;
		long _requestsHttpTotal;
		int _requestsHttpInFlight;
		long _cacheL1Hit304;
		long _cacheL1Hit200;
		long _cacheL1Miss;
		long _cacheL1Bypass;
		long _cacheL2Hit304;
		long _cacheL2Hit200;
		long _cacheL2Miss;
		long _cacheL2Bypass;
		long _rpcEntered;
		int _rpcInFlight;
		long _rpcRejected;
		long _rpcCompleted;
		long _rpcLatencyTotal;
		long _rpcMaxLatency;

		long _lastRequestsTotal;
		long _lastRequestsHttpTotal;
		long _lastRpcEntered;
		long _lastRpcCompleted;

		double GetRate(ref long last, long current, double elapsed)
		{
			if (elapsed <= 0)
				return 0;

			var delta = current - Interlocked.Exchange(ref last, current);
			return delta > 0 ? delta / elapsed : 0;
		}

		public void IncreaseRequest(bool updateHttp = true)
		{
			Interlocked.Increment(ref this._requestsTotal);
			Interlocked.Increment(ref this._requestsInFlight);

			if (updateHttp)
			{
				Interlocked.Increment(ref this._requestsHttpTotal);
				Interlocked.Increment(ref this._requestsHttpInFlight);
			}
		}

		public void DecreaseRequest(bool updateHttp = true)
		{
			if (Interlocked.Decrement(ref this._requestsInFlight) < 0)
				Interlocked.Exchange(ref this._requestsInFlight, 0);

			if (updateHttp)
			{
				if (Interlocked.Decrement(ref this._requestsHttpInFlight) < 0)
					Interlocked.Exchange(ref this._requestsHttpInFlight, 0);
			}
		}

		public long RequestsTotal => Volatile.Read(ref this._requestsTotal);

		public int RequestsInFlight => Volatile.Read(ref this._requestsInFlight);

		public long RequestsHttpTotal => Volatile.Read(ref this._requestsHttpTotal);

		public int RequestsHttpInFlight => Volatile.Read(ref this._requestsHttpInFlight);

		public double GetRequestsRate(double elapsedSeconds, bool useHttp = false)
			=> useHttp ? this.GetRequestsHttpRate(elapsedSeconds) : this.GetRate(ref this._lastRequestsTotal, this.RequestsTotal, elapsedSeconds);

		public double GetRequestsHttpRate(double elapsedSeconds)
			=> this.GetRate(ref this._lastRequestsHttpTotal, this.RequestsHttpTotal, elapsedSeconds);

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

		public long L1Bypass()
			=> Interlocked.Increment(ref this._cacheL1Bypass);

		public long CacheL1BypassCount => Volatile.Read(ref this._cacheL1Bypass);

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

		public long L2Bypass()
			=> Interlocked.Increment(ref this._cacheL2Bypass);

		public long CacheL2BypassCount => Volatile.Read(ref this._cacheL2Bypass);

		double GetRatio(long count, bool useHttp = false)
		{
			var total = useHttp ? this.RequestsHttpTotal : this.RequestsTotal;
			return total > 0 ? count * 100.0 / total : 0;
		}

		public double GetCacheL1HitRatio(bool useHttp = true)
			=> this.GetRatio(this.CacheL1HitCount, useHttp);

		public double GetCacheL1MissRatio(bool useHttp = true)
			=> this.GetRatio(this.CacheL1MissCount, useHttp);

		public double GetCacheL1BypassRatio(bool useHttp = true)
			=> this.GetRatio(this.CacheL1BypassCount, useHttp);

		public double GetCacheL2HitRatio(bool useHttp = true)
			=> this.GetRatio(this.CacheL2HitCount, useHttp);

		public double GetCacheL2MissRatio(bool useHttp = true)
			=> this.GetRatio(this.CacheL2MissCount, useHttp);

		public double GetCacheL2BypassRatio(bool useHttp = true)
			=> this.GetRatio(this.CacheL2BypassCount, useHttp);

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
			=> this.GetRate(ref this._lastRpcEntered, this.RpcEnteredCount, elapsedSeconds);

		public double GetRpcCompletedRate(double elapsedSeconds)
			=> this.GetRate(ref this._lastRpcCompleted, this._rpcCompleted, elapsedSeconds);
	}
}