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
 * This file is part of Zongsoft.Scheduling library.
 *
 * The Zongsoft.Scheduling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3.0 of the License,
 * or (at your option) any later version.
 *
 * The Zongsoft.Scheduling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the Zongsoft.Scheduling library. If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Threading;

using Zongsoft.Services;

namespace Zongsoft.Scheduling.Commands
{
	[CommandOption(KEY_LIMIT_OPTION, typeof(int), 10, "${Text.SchedulerInfoCommand.Options.Limit}")]
	public class SchedulerInfoCommand : Zongsoft.Services.Commands.WorkerInfoCommand
	{
		#region 常量定义
		private const string KEY_LIMIT_OPTION = "limit";
		#endregion

		#region 构造函数
		public SchedulerInfoCommand()
		{
		}

		public SchedulerInfoCommand(string name) : base(name)
		{
		}
		#endregion

		#region 重写方法
		protected override void Info(CommandContext context, IWorker worker)
		{
			if(worker is IScheduler scheduler)
			{
				//构造基本信息内容
				var content = SchedulerCommand.GetInfo(scheduler, true).AppendLine();

				//获取“limit”命令参数
				var limit = context.Expression.Options.GetValue<int>(KEY_LIMIT_OPTION);

				if(limit > 0)
				{
					var index = 0;

					//遍历生成触发器信息
					foreach(var trigger in scheduler.Triggers)
					{
						if(index == limit)
						{
							content.AppendLine(CommandOutletColor.DarkMagenta, "\t... ...");
							break;
						}

						//获取当前触发器下的处理器集合
						var tokens = scheduler.GetHandlers(trigger);

						content.Append(CommandOutletColor.DarkYellow, $"[{++index}] ")
						       .Append(CommandOutletColor.DarkGreen, trigger.ToString())
						       .AppendLine(CommandOutletColor.DarkMagenta, $" ({tokens.Length})");

						if(!string.IsNullOrWhiteSpace(trigger.Description))
							content.AppendLine(CommandOutletColor.DarkGray, trigger.Description);

						//遍历生成处理器信息
						for(int i = 0; i < tokens.Length; i++)
						{
							if(i >= limit)
							{
								content.AppendLine(CommandOutletColor.DarkMagenta, "\t... ...");
								break;
							}

							content.Append(CommandOutletColor.DarkCyan, $"    {tokens[i].ScheduleId, 5}")
							       .Append(CommandOutletColor.DarkGray, " : ")
							       .AppendLine(tokens[i].ToString());
						}
					}
				}

				//输出整个信息内容
				context.Output.WriteLine(content);
			}
			else
			{
				//调用基类同名方法
				base.Info(context, worker);
			}
		}
		#endregion
	}
}
