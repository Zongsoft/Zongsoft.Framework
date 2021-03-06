﻿/*
 *   _____                                ______
 *  /_   /  ____  ____  ____  _________  / __/ /_
 *    / /  / __ \/ __ \/ __ \/ ___/ __ \/ /_/ __/
 *   / /__/ /_/ / / / / /_/ /\_ \/ /_/ / __/ /_
 *  /____/\____/_/ /_/\__  /____/\____/_/  \__/
 *                   /____/
 *
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@gmail.com>
 *
 * Copyright (C) 2010-2020 Zongsoft Studio <http://www.zongsoft.com>
 *
 * This file is part of Zongsoft.Core library.
 *
 * The Zongsoft.Core is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Core is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Core library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

namespace Zongsoft.Messaging
{
	public abstract class MessageQueueBase : Zongsoft.Collections.IQueue
	{
		#region 事件定义
		public event EventHandler<Zongsoft.Collections.DequeuedEventArgs> Dequeued;
		public event EventHandler<Zongsoft.Collections.EnqueuedEventArgs> Enqueued;
		#endregion

		#region 成员字段
		private readonly string _name;
		#endregion

		#region 构造函数
		protected MessageQueueBase(string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException(nameof(name));

			_name = name.Trim();
		}
		#endregion

		#region 公共属性
		public virtual string Name
		{
			get => _name;
		}

		public long Count
		{
			get => this.GetCount();
		}
		#endregion

		#region 保护属性
		protected virtual int Capacity
		{
			get => 0;
		}
		#endregion

		#region 公共方法
		public abstract long GetCount();

		public abstract Task<long> GetCountAsync();

		public virtual void Enqueue(object item, MessageEnqueueSettings settings = null)
		{
			this.OnEnqueue(item, settings);
			this.OnEnqueued(item, settings);
		}

		public virtual void EnqueueMany<T>(IEnumerable<T> items, MessageEnqueueSettings settings = null)
		{
			if(items == null)
				throw new ArgumentNullException(nameof(items));

			foreach(var item in items)
			{
				this.Enqueue(item, settings);
			}
		}

		public virtual Task EnqueueAsync(object item, MessageEnqueueSettings settings = null, CancellationToken cancellation = default)
		{
			return this.OnEnqueueAsync(item, settings, cancellation)
			           .ContinueWith(task =>
			           {
						   if(task.IsCompletedSuccessfully)
							   this.OnEnqueued(item, settings);
			           }, cancellation);
		}

		public virtual async Task EnqueueManyAsync<TItem>(IEnumerable<TItem> items, MessageEnqueueSettings settings = null, CancellationToken cancellation = default)
		{
			if(items == null)
				throw new ArgumentNullException(nameof(items));

			cancellation.ThrowIfCancellationRequested();

			foreach(var item in items)
			{
				await this.EnqueueAsync(item, settings, cancellation);
			}
		}

		public virtual MessageBase Dequeue(MessageDequeueSettings settings = null)
		{
			var value = this.OnDequeue(settings);
			this.OnDequeued(value, settings);
			return value;
		}

		public virtual IEnumerable<MessageBase> DequeueMany(int count, MessageDequeueSettings settings = null)
		{
			if(count <= 0)
				throw new ArgumentOutOfRangeException(nameof(count));

			for(int i = 0; i < count; i++)
				yield return this.Dequeue(settings);
		}

		public virtual Task<MessageBase> DequeueAsync(MessageDequeueSettings settings = null, CancellationToken cancellation = default)
		{
			return this.OnDequeueAsync(settings, cancellation)
			           .ContinueWith(task =>
					   {
						   if(task.IsCompletedSuccessfully)
							   this.OnDequeued(task.Result, settings);

						   return task.Result;
					   }, cancellation);
		}

		public virtual async IAsyncEnumerable<MessageBase> DequeueManyAsync(int count, MessageDequeueSettings settings = null, [EnumeratorCancellation]CancellationToken cancellation = default)
		{
			if(count <= 0)
				throw new ArgumentOutOfRangeException(nameof(count));

			cancellation.ThrowIfCancellationRequested();

			for(int i = 0; i < count; i++)
				yield return await this.DequeueAsync(settings, cancellation);
		}

		public abstract MessageBase Peek();

		public abstract Task<MessageBase> PeekAsync(CancellationToken cancellation = default);
		#endregion

		#region 队列实现
		void Zongsoft.Collections.IQueue.Clear()
		{
			this.ClearQueue();
		}

		Task Zongsoft.Collections.IQueue.ClearAsync(CancellationToken cancellation)
		{
			cancellation.ThrowIfCancellationRequested();
			this.ClearQueue();
			return Task.CompletedTask;
		}

		void Zongsoft.Collections.IQueue.Enqueue(object item, object settings)
		{
			this.Enqueue(item, this.GetEnqueueSettings(settings));
		}

		void Zongsoft.Collections.IQueue.EnqueueMany<T>(IEnumerable<T> items, object settings)
		{
			this.EnqueueMany(items, this.GetEnqueueSettings(settings));
		}

		Task Zongsoft.Collections.IQueue.EnqueueAsync(object item, object settings, CancellationToken cancellation)
		{
			return this.EnqueueAsync(item, this.GetEnqueueSettings(settings), cancellation);
		}

		Task Zongsoft.Collections.IQueue.EnqueueManyAsync<T>(IEnumerable<T> items, object settings, CancellationToken cancellation)
		{
			return this.EnqueueManyAsync(items, this.GetEnqueueSettings(settings), cancellation);
		}

		object Zongsoft.Collections.IQueue.Dequeue(object settings)
		{
			return this.Dequeue(this.GetDequeueSettings(settings));
		}

		IEnumerable Zongsoft.Collections.IQueue.DequeueMany(int count, object settings)
		{
			return this.DequeueMany(count, this.GetDequeueSettings(settings));
		}

		async Task<object> Zongsoft.Collections.IQueue.DequeueAsync(object settings, CancellationToken cancellation)
		{
			return await this.DequeueAsync(this.GetDequeueSettings(settings), cancellation);
		}

		IAsyncEnumerable<object> Zongsoft.Collections.IQueue.DequeueManyAsync(int count, object settings, CancellationToken cancellation)
		{
			return this.DequeueManyAsync(count, this.GetDequeueSettings(settings), cancellation);
		}

		object Zongsoft.Collections.IQueue.Peek()
		{
			return this.Peek();
		}

		async Task<object> Zongsoft.Collections.IQueue.PeekAsync(CancellationToken cancellation)
		{
			return await this.PeekAsync(cancellation);
		}
		#endregion

		#region 保护方法
		protected virtual MessageDequeueSettings GetDequeueSettings(object settings)
		{
			return settings as MessageDequeueSettings;
		}

		protected virtual MessageEnqueueSettings GetEnqueueSettings(object settings)
		{
			return settings as MessageEnqueueSettings;
		}

		protected virtual void ClearQueue()
		{
			throw new NotSupportedException("The message queue does not support the operation.");
		}

		protected virtual void CopyQueueTo(Array array, int index)
		{
			throw new NotSupportedException("The message queue does not support the operation.");
		}

		protected abstract void OnEnqueue(object item, MessageEnqueueSettings settings);
		protected abstract Task OnEnqueueAsync(object item, MessageEnqueueSettings settings, CancellationToken cancellation);
		protected abstract MessageBase OnDequeue(MessageDequeueSettings settings);
		protected abstract Task<MessageBase> OnDequeueAsync(MessageDequeueSettings settings, CancellationToken cancellation);
		#endregion

		#region 激发事件
		protected virtual void OnDequeued(object value, object settings)
		{
			this.Dequeued?.Invoke(this, new Collections.DequeuedEventArgs(value, settings, Collections.CollectionRemovedReason.Remove));
		}

		protected virtual void OnEnqueued(object value, object settings)
		{
			this.Enqueued?.Invoke(this, new Collections.EnqueuedEventArgs(value, settings));
		}
		#endregion

		#region 显式实现
		int Zongsoft.Collections.IQueue.Capacity
		{
			get => this.Capacity;
		}

		int ICollection.Count
		{
			get => (int)this.Count;
		}

		bool ICollection.IsSynchronized
		{
			get => false;
		}

		object ICollection.SyncRoot
		{
			get => throw new NotSupportedException("The message queue does not support the operation.");
		}

		void ICollection.CopyTo(Array array, int index)
		{
			this.CopyQueueTo(array, index);
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			throw new NotSupportedException("The message queue does not support the operation.");
		}
		#endregion
	}
}
