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

namespace Zongsoft.IO
{
	[Serializable]
	public class DirectoryInfo : PathInfo
	{
		#region 构造函数
		protected DirectoryInfo()
		{
		}

		public DirectoryInfo(string path, DateTime? createdTime = null, DateTime? modifiedTime = null, string url = null)
			: base(path, createdTime, modifiedTime, url)
		{
		}

		public DirectoryInfo(Path path, DateTime? createdTime = null, DateTime? modifiedTime = null, string url = null)
			: base(path, createdTime, modifiedTime, url)
		{
		}
		#endregion

		#region 重写属性
		public override bool IsFile
		{
			get
			{
				return false;
			}
		}

		public override bool IsDirectory
		{
			get
			{
				return true;
			}
		}
		#endregion
	}
}
