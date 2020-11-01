﻿/*
 *    _____                                ____
 *   /_   /  ____  ____  ____  ____ ____  / __/_
 *     / /  / __ \/ __ \/ __ \/ ___/ __ \/ /_/ /_
 *    / /__/ /_/ / / / / /_/ /\_ \/ /_/ / __  __/
 *   /____/\____/_/ /_/\__  /____/\____/_/ / /_
 *                    /____/               \__/
 *
 * Authors:
 *   钟峰(Popeye Zhong) <zongsoft@qq.com>
 *
 * The MIT License (MIT)
 * 
 * Copyright (C) 2018 Zongsoft Corporation <http://www.zongsoft.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
 
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;

namespace Zongsoft.Scheduling.Samples
{
	public class MyScheduler : Scheduler<uint, Models.PlanModel>
	{
		#region 构造函数
		public MyScheduler() { }
		#endregion

		#region 重写方法
		protected override ITrigger GetTrigger(ISchedule<uint, Models.PlanModel> schedule)
		{
			if(schedule == null || string.IsNullOrWhiteSpace(schedule.Data.CronExpression))
				return null;

			try
			{
				//因为无效的Cron表达式可能会导致解析异常，所以需要捕获异常
				return Trigger.Cron(schedule.Data.CronExpression, schedule.Data.ExpirationTime, schedule.Data.EffectiveTime);
			}
			catch(Exception ex)
			{
				Zongsoft.Diagnostics.Logger.Error(ex);
			}

			return null;
		}

		protected override IHandler GetHandler(ISchedule<uint, Models.PlanModel> schedule)
		{
			return MyHandler.Default;
		}

		protected override IEnumerable<ISchedule<uint, Models.PlanModel>> GetSchedules(IEnumerable<uint> keys)
		{
			//建集为空，模拟全量初始化
			if(keys == null)
			{
				for(int i = 0; i < 200; i++)
				{
					yield return new MySchedule(new Models.PlanModel((uint)(i + 1), null, GenerateCron()));
				}

				yield break;
			}

			foreach(var key in keys)
			{
				yield return new MySchedule(new Models.PlanModel(key, null, GenerateCron()));
			}
		}
		#endregion

		#region 私有方法
		private string GenerateCron()
		{
			return (Common.Randomizer.GenerateInt32() % 6) switch
			{
				0 => "0 * * * * ?",                //每分钟来一发
				1 => "0 0/5 * * * ?",              //每5分钟来一发
				2 => "0 0,10,20,30,40,50 * * * ?", //每10分钟来一发
				3 => "0 0,30 * * * ?",             //每30分钟来一发
				4 => "0 0 0/2 * * ?",              //每2个小时来一发
				5 => "0 0 * ? * 1-5",              //工作日（周一至周五）的每小时来一发
				_ => "0 0 * * * ?",                //负数：每小时整点来一发
			};
		}
		#endregion
	}

	public class MySchedule : ISchedule<uint, Models.PlanModel>
	{
		public MySchedule(Models.PlanModel data)
		{
			this.Data = data ?? throw new ArgumentNullException(nameof(data));
		}

		public uint Key { get => this.Data.PlanId; }
		public long ScheduleId { get; set; }
		public Models.PlanModel Data { get; set; }
		object ISchedule.Data { get => this.Data; set => this.Data = value as Models.PlanModel; }
	}
}
