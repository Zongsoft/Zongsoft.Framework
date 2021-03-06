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
 * This file is part of Zongsoft.Externals.WeChat library.
 *
 * The Zongsoft.Externals.WeChat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Externals.WeChat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Externals.WeChat library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;

namespace Zongsoft.Externals.Wechat
{
	/// <summary>
	/// 表示微信平台API返回的错误消息的结构。
	/// </summary>
	public struct ErrorResult
	{
		#region 构造函数
		public ErrorResult(int code, string message)
		{
			this.Code = code;
			this.Message = message;
		}
		#endregion

		#region 公共属性
		[Zongsoft.Serialization.SerializationMember(Ignored = true)]
		[System.Text.Json.Serialization.JsonIgnore]
		public bool IsFailed { get => this.Code != 0; }

		[Zongsoft.Serialization.SerializationMember(Ignored = true)]
		[System.Text.Json.Serialization.JsonIgnore]
		public bool IsSucceed { get => this.Code == 0; }

		/// <summary>获取或设置错误码。</summary>
		[Zongsoft.Serialization.SerializationMember("errcode")]
		[System.Text.Json.Serialization.JsonPropertyName("errcode")]
		public int Code { get; set; }

		/// <summary>获取或设置错误消息。</summary>
		[Zongsoft.Serialization.SerializationMember("errmsg")]
		[System.Text.Json.Serialization.JsonPropertyName("errmsg")]
		public string Message { get; set; }
		#endregion

		#region 重写方法
		public override string ToString()
		{
			return "[" + this.Code.ToString() + "] " + this.Message;
		}
		#endregion

		public static readonly ErrorResult Empty = new ErrorResult();
		public static readonly ErrorResult Succeed = new ErrorResult();
	}
}
