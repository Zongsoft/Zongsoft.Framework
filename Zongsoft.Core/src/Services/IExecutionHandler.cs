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
using System.Threading.Tasks;

namespace Zongsoft.Services
{
	/// <summary>
	/// 提供执行处理程序的功能。
	/// </summary>
	public interface IExecutionHandler
	{
		/// <summary>
		/// 确认当前处理程序能否处理本次执行请求。
		/// </summary>
		/// <param name="context">当前执行的上下文对象。</param>
		/// <returns>如果能处理本次执行请求则返回真(true)，否则返回假(false)。</returns>
		bool CanHandle(object context);

		/// <summary>
		/// 同步处理执行请求。
		/// </summary>
		/// <param name="context">当前执行的上下文对象。</param>
		void Handle(object context);

        /// <summary>
        /// 异步处理执行请求。
        /// </summary>
        /// <param name="context">当前执行的上下文对象。</param>
        /// <returns>返回的异步任务。</returns>
        Task HandleAsync(object context);
	}
}
