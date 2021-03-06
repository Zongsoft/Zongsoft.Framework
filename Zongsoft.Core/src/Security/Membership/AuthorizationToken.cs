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
using System.Linq;
using System.Collections.Generic;

namespace Zongsoft.Security.Membership
{
	public struct AuthorizationToken : IEquatable<AuthorizationToken>
	{
		#region 构造函数
		public AuthorizationToken(string schema, params ActionToken[] actions)
		{
			this.Schema = schema ?? throw new ArgumentNullException(nameof(schema));
			this.Actions = actions ?? Array.Empty<ActionToken>();
		}

		public AuthorizationToken(string schema, IEnumerable<ActionToken> actions)
		{
			this.Schema = schema ?? throw new ArgumentNullException(nameof(schema));
			this.Actions = actions == null ? Array.Empty<ActionToken>() : actions.ToArray();
		}
		#endregion

		#region 公共属性
		/// <summary>授权的资源标识。</summary>
		public string Schema { get; }

		/// <summary>授权的操作集。</summary>
		public ActionToken[] Actions { get; }
		#endregion

		#region 公共方法
		public bool HasAction(string action)
		{
			if(string.IsNullOrEmpty(action))
				return false;

			return this.Actions.Any(token => string.Equals(token.Action, action, StringComparison.OrdinalIgnoreCase));
		}
		#endregion

		#region 重写方法
		public bool Equals(AuthorizationToken other)
		{
			return string.Equals(this.Schema, other.Schema, StringComparison.OrdinalIgnoreCase);
		}

		public override bool Equals(object obj)
		{
			if(obj == null || obj.GetType() != this.GetType())
				return false;

			return this.Equals((AuthorizationToken)obj);
		}

		public override int GetHashCode()
		{
			return this.Schema.ToUpperInvariant().GetHashCode();
		}

		public override string ToString()
		{
			if(this.Actions == null || this.Actions.Length == 0)
				return this.Schema;
			else
				return this.Schema + "(" + string.Join(",", this.Actions) + ")";
		}
		#endregion

		#region 嵌套结构
		public struct ActionToken : IEquatable<ActionToken>
		{
			#region 构造函数
			public ActionToken(string action, string filter = null)
			{
				this.Action = action ?? throw new ArgumentNullException(nameof(action));
				this.Filter = filter;
			}
			#endregion

			#region 公共属性
			/// <summary>授权的操作标识。</summary>
			public string Action { get; }

			/// <summary>授权的过滤表达式。</summary>
			public string Filter { get; }
			#endregion

			#region 重写方法
			public bool Equals(ActionToken other)
			{
				return string.Equals(this.Action, other.Action, StringComparison.OrdinalIgnoreCase);
			}

			public override bool Equals(object obj)
			{
				if(obj == null || obj.GetType() != this.GetType())
					return false;

				return this.Equals((ActionToken)obj);
			}

			public override int GetHashCode()
			{
				return this.Action.ToUpperInvariant().GetHashCode();
			}

			public override string ToString()
			{
				if(string.IsNullOrEmpty(this.Filter))
					return this.Action;
				else
					return this.Action + ":" + this.Filter;
			}
			#endregion
		}
		#endregion
	}
}
