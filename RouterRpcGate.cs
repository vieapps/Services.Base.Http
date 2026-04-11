using System;
using System.Threading;
using System.Threading.Tasks;

namespace net.vieapps.Services
{
	public sealed class RouterRpcGate
	{
		readonly SemaphoreSlim _semaphore;
		readonly int _max;
		readonly int _millisecondsTimeout;
		int _current;

		public RouterRpcGate(int max, int millisecondsTimeout = 50)
		{
			if (max <= 0)
				throw new ArgumentOutOfRangeException(nameof(max));
			if (millisecondsTimeout < 0)
				throw new ArgumentOutOfRangeException(nameof(millisecondsTimeout));
			this._max = max;
			this._millisecondsTimeout = millisecondsTimeout;
			this._semaphore = new SemaphoreSlim(max, max);
		}

		public int Current => Volatile.Read(ref this._current);

		public int Max => this._max;

		public int Available => this._max - this.Current;

		public double Usage => (double)this.Current / this._max;

		public async ValueTask<Releaser?> TryEnterAsync(CancellationToken cancellationToken = default)
		{
			if (Volatile.Read(ref this._current) >= this._max)
				return null;
			if (!await this._semaphore.WaitAsync(this._millisecondsTimeout, cancellationToken).ConfigureAwait(false))
				return null;
			Interlocked.Increment(ref this._current);
			return new Releaser(this);
		}

		internal void Release()
		{
			if (Interlocked.Decrement(ref this._current) < 0)
				Interlocked.Exchange(ref this._current, 0);
			this._semaphore.Release();
		}

		public readonly struct Releaser : IDisposable
		{
			readonly RouterRpcGate _gate;
			internal Releaser(RouterRpcGate gate) => this._gate = gate;
			public void Dispose() => this._gate?.Release();
		}
	}
}