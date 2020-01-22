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
using System.Collections.Generic;

namespace Zongsoft.Data
{
	/// <summary>
	/// 表示数据搜索器的泛型接口。
	/// </summary>
	/// <typeparam name="TEntity">关于搜索服务对应的数据实体类型。</typeparam>
	public interface IDataSearcher<TEntity> : IDataSearcher
	{
		new IEnumerable<TEntity> Search(string keyword, params Sorting[] sortings);
		new IEnumerable<TEntity> Search(string keyword, IDictionary<string, object> states, params Sorting[] sortings);
		new IEnumerable<TEntity> Search(string keyword, Paging paging, params Sorting[] sortings);
		new IEnumerable<TEntity> Search(string keyword, string schema, params Sorting[] sortings);
		new IEnumerable<TEntity> Search(string keyword, string schema, IDictionary<string, object> states, params Sorting[] sortings);
		new IEnumerable<TEntity> Search(string keyword, string schema, Paging paging, params Sorting[] sortings);
		new IEnumerable<TEntity> Search(string keyword, string schema, Paging paging, IDictionary<string, object> states, params Sorting[] sortings);
	}
}
