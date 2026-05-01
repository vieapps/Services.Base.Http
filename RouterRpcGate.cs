using System;
using System.Threading;
using System.Threading.Tasks;
namespace net.vieapps.Services
{
	public sealed class RouterRpcGate
	{
		int _hardMax;
		int _softMax;
		int _inflight;

		readonly SemaphoreSlim _semaphore;
		readonly int _timeoutMilliseconds;

		readonly object _locker = new object();
		readonly int _increaseIntervalMilliseconds = 150;
		readonly int _cooldownMilliseconds = 2000;
		readonly int _increaseStep = 1;

		int _ticking;
		Timer _timer;

		long _lastIncreaseTicks;
		long _lastDecreaseTicks;

		public readonly struct Releaser : IDisposable
		{
			readonly RouterRpcGate _rpcgate;
			readonly int _weight;
			readonly bool _usedSemaphore;

			internal Releaser(RouterRpcGate rpcgate, int weight, bool usedSemaphore)
			{
				this._rpcgate = rpcgate;
				this._weight = weight;
				this._usedSemaphore = usedSemaphore;
			}

			public void Dispose() => this._rpcgate?.Release(this._weight, this._usedSemaphore);
		}

		public int Current => Volatile.Read(ref this._inflight);

		public int Max => Volatile.Read(ref this._softMax);

		public int Available => this.Max - this.Current;

		public double Usage => (double)this.Current / Math.Max(1, this.Max);

		public RouterRpcGate(int max, int timeoutMilliseconds = 50)
		{
			if (max <= 0)
				throw new ArgumentOutOfRangeException(nameof(max));

			if (timeoutMilliseconds < 0)
				throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));

			this._hardMax = max;
			this._softMax = max;
			this._timeoutMilliseconds = timeoutMilliseconds;
			this._semaphore = new SemaphoreSlim(max, Int32.MaxValue);
		}

		public ValueTask<Releaser?> TryEnterAsync(CancellationToken cancellationToken = default)
			=> this.TryEnterAsync(1, cancellationToken);

		public async ValueTask<Releaser?> TryEnterAsync(int weight, CancellationToken cancellationToken)
		{
			if (weight <= 0)
				throw new ArgumentOutOfRangeException(nameof(weight));

			while (true)
			{
				var current = Volatile.Read(ref this._inflight);
				var capacity = Volatile.Read(ref this._softMax);
				if (weight > capacity - current)
					break;

				if (Interlocked.CompareExchange(ref this._inflight, current + weight, current) == current)
					return new Releaser(this, weight, false);
			}

			if (this._timeoutMilliseconds <= 0)
				return null;

			if (!await this._semaphore.WaitAsync(this._timeoutMilliseconds, cancellationToken).ConfigureAwait(false))
				return null;

			while (true)
			{
				var current = Volatile.Read(ref this._inflight);
				var capacity = Volatile.Read(ref this._softMax);
				if (weight > capacity - current)
				{
					this._semaphore.Release();
					return null;
				}

				if (Interlocked.CompareExchange(ref this._inflight, current + weight, current) == current)
					return new Releaser(this, weight, true);
			}
		}

		internal void Release(int weight, bool usedSemaphore)
		{
			Interlocked.Add(ref this._inflight, -weight);
			if (usedSemaphore)
				this._semaphore.Release();
		}

		public void SetMaxCapacity(int newMaxCapacity)
		{
			if (newMaxCapacity <= 0)
				throw new ArgumentOutOfRangeException(nameof(newMaxCapacity));

			Volatile.Write(ref this._hardMax, newMaxCapacity);
			var softMax = Volatile.Read(ref this._softMax);
			if (newMaxCapacity < softMax)
			{
				Volatile.Write(ref this._softMax, newMaxCapacity);
				Volatile.Write(ref this._lastDecreaseTicks, this.TickCount);
			}
			else if (newMaxCapacity > softMax)
				this.StartTimer();
		}

		void StartTimer()
		{
			var timer = Volatile.Read(ref this._timer);
			if (timer == null)
			{
				lock (this._locker)
				{
					if (this._timer == null)
						this._timer = new Timer(_ => this.OnTimerTick(), null, this._increaseIntervalMilliseconds, this._increaseIntervalMilliseconds);
				}
			}
		}

		void StopTimer()
		{
			lock (this._locker)
			{
				var timer = this._timer;
				this._timer = null;
				timer?.Dispose();
			}
		}

		void OnTimerTick()
		{
			if (Interlocked.Exchange(ref this._ticking, 1) == 1)
				return;

			try
			{
				var now = this.TickCount;
				var hardMax = Volatile.Read(ref this._hardMax);
				var softMax = Volatile.Read(ref this._softMax);

				if (softMax >= hardMax)
				{
					this.StopTimer();
					return;
				}

				if (!RouterRpcGate.Elapsed(now, Volatile.Read(ref this._lastDecreaseTicks), this._cooldownMilliseconds))
					return;

				if (!RouterRpcGate.Elapsed(now, Volatile.Read(ref this._lastIncreaseTicks), this._increaseIntervalMilliseconds))
					return;

				var inflight = Volatile.Read(ref this._inflight);
				if (inflight >= (int)(softMax * 0.8))
					return;

				var next = Math.Min(hardMax, softMax + this._increaseStep);
				Volatile.Write(ref this._softMax, next);
				Volatile.Write(ref this._lastIncreaseTicks, now);
			}
			finally
			{
				this._ticking = 0;
			}
		}

#if NETSTANDARD2_0
		long TickCount
			=> (long)Environment.TickCount;

		static bool Elapsed(long now, long last, int milliseconds) => unchecked((int)(now - last)) >= milliseconds;
#else
		long TickCount => Environment.TickCount64;

		static bool Elapsed(long now, long last, int milliseconds) => (now - last) >= milliseconds;
#endif
	}
}