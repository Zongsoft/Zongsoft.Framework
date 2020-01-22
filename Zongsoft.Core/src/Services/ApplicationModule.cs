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

using Zongsoft.Options;
using Zongsoft.ComponentModel;
using Zongsoft.Collections;

namespace Zongsoft.Services
{
	[System.Reflection.DefaultMember(nameof(Schemas))]
	public class ApplicationModule : IApplicationModule
	{
		#region 构造函数
		public ApplicationModule(string name)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException(nameof(name));

			this.Name = this.Title = name.Trim();
			this.Schemas = new SchemaCollection();
		}

		public ApplicationModule(string name, string title, string description = null)
		{
			if(string.IsNullOrWhiteSpace(name))
				throw new ArgumentNullException(nameof(name));

			this.Name = name.Trim();
			this.Title = title ?? this.Name;
			this.Description = description;
			this.Schemas = new SchemaCollection();
		}
		#endregion

		#region 公共属性
		public string Name
		{
			get;
		}

		public string Title
		{
			get; set;
		}

		public string Description
		{
			get; set;
		}

		public virtual ISettingsProvider Settings
		{
			get => OptionManager.Instance.Settings;
		}

		public virtual IServiceProvider Services
		{
			get => ServiceProviderFactory.Instance.GetProvider(this.Name);
		}

		public INamedCollection<Schema> Schemas
		{
			get;
		}
		#endregion

		#region 重写方法
		public override string ToString()
		{
			if(string.IsNullOrEmpty(this.Title) || string.Equals(this.Name, this.Title))
				return this.Name;
			else
				return string.Format("[{0}] {1}", this.Name, this.Title);
		}
		#endregion
	}
}
