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
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Linq.Expressions;

namespace Zongsoft.Data
{
	/// <summary>
	/// 表示数据过滤条件的设置项。
	/// </summary>
	public class Condition : ICondition, IEquatable<Condition>
	{
		#region 构造函数
		public Condition(string name, object value, ConditionOperator @operator = ConditionOperator.Equal)
		{
			this.Field = Operand.Field(name);
			this.Value = value;
			this.Operator = @operator;
			this.Name = name;
		}

		public Condition(Operand field, object value, ConditionOperator @operator = ConditionOperator.Equal)
		{
			this.Field = field ?? throw new ArgumentNullException(nameof(field));
			this.Value = value;
			this.Operator = @operator;
			this.Name = (field as Operand.FieldOperand)?.Name;
		}
		#endregion

		#region 公共属性
		/// <summary>获取条件项的名称。</summary>
		public string Name { get; }

		/// <summary>获取条件项的字段域(左操作元)。</summary>
		public Operand Field { get; }

		/// <summary>获取或设置条件项的比对值(右操作元)。</summary>
		public object Value { get; set; }

		/// <summary>获取或设置条件项的操作符。</summary>
		public ConditionOperator Operator { get; set; }
		#endregion

		#region 静态方法
		public static Condition Equal(string name, object value)
		{
			return new Condition(name, value, ConditionOperator.Equal);
		}

		public static Condition Equal(string name, Operand value)
		{
			return new Condition(name, value, ConditionOperator.Equal);
		}

		public static Condition Equal(Operand field, Operand value)
		{
			return new Condition(field, value, ConditionOperator.Equal);
		}

		public static Condition NotEqual(string name, object value)
		{
			return new Condition(name, value, ConditionOperator.NotEqual);
		}

		public static Condition NotEqual(string name, Operand value)
		{
			return new Condition(name, value, ConditionOperator.NotEqual);
		}

		public static Condition NotEqual(Operand field, Operand value)
		{
			return new Condition(field, value, ConditionOperator.NotEqual);
		}

		public static Condition GreaterThan(string name, object value)
		{
			return new Condition(name, value, ConditionOperator.GreaterThan);
		}

		public static Condition GreaterThan(string name, Operand value)
		{
			return new Condition(name, value, ConditionOperator.GreaterThan);
		}

		public static Condition GreaterThan(Operand field, Operand value)
		{
			return new Condition(field, value, ConditionOperator.GreaterThan);
		}

		public static Condition GreaterThanEqual(string name, object value)
		{
			return new Condition(name, value, ConditionOperator.GreaterThanEqual);
		}

		public static Condition GreaterThanEqual(string name, Operand value)
		{
			return new Condition(name, value, ConditionOperator.GreaterThanEqual);
		}

		public static Condition GreaterThanEqual(Operand field, Operand value)
		{
			return new Condition(field, value, ConditionOperator.GreaterThanEqual);
		}

		public static Condition LessThan(string name, object value)
		{
			return new Condition(name, value, ConditionOperator.LessThan);
		}

		public static Condition LessThan(string name, Operand value)
		{
			return new Condition(name, value, ConditionOperator.LessThan);
		}

		public static Condition LessThan(Operand field, Operand value)
		{
			return new Condition(field, value, ConditionOperator.LessThan);
		}

		public static Condition LessThanEqual(string name, object value)
		{
			return new Condition(name, value, ConditionOperator.LessThanEqual);
		}

		public static Condition LessThanEqual(string name, Operand value)
		{
			return new Condition(name, value, ConditionOperator.LessThanEqual);
		}

		public static Condition LessThanEqual(Operand field, Operand value)
		{
			return new Condition(field, value, ConditionOperator.LessThanEqual);
		}

		public static Condition Like(string name, string value)
		{
			if(string.IsNullOrEmpty(value))
				return new Condition(name, value, ConditionOperator.Equal);
			else
				return new Condition(name, value, ConditionOperator.Like);
		}

		public static Condition Like(Operand field, string value)
		{
			if(string.IsNullOrEmpty(value))
				return new Condition(field, value, ConditionOperator.Equal);
			else
				return new Condition(field, value, ConditionOperator.Like);
		}

		public static Condition Between<T>(string name, Range<T> range) where T : struct, IComparable<T>
		{
			return range.ToCondition(name);
		}

		public static Condition Between<T>(string name, T minimum, T maximum) where T : struct, IComparable<T>
		{
			return (new Range<T>(minimum, maximum)).ToCondition(name);
		}

		public static Condition Between<T>(string name, T? minimum, T? maximum) where T : struct, IComparable<T>
		{
			if(minimum == null && maximum == null)
				return null;

			return (new Range<T>(minimum, maximum)).ToCondition(name);
		}

		public static Condition In<T>(string name, IEnumerable<T> values) where T : IEquatable<T>
		{
			if(values == null)
				throw new ArgumentNullException(nameof(values));

			return new Condition(name, values, ConditionOperator.In);
		}

		public static Condition In<T>(string name, params T[] values) where T : IEquatable<T>
		{
			if(values == null)
				throw new ArgumentNullException(nameof(values));

			return new Condition(name, values, ConditionOperator.In);
		}

		public static Condition NotIn<T>(string name, IEnumerable<T> values) where T : IEquatable<T>
		{
			if(values == null)
				throw new ArgumentNullException(nameof(values));

			return new Condition(name, values, ConditionOperator.NotIn);
		}

		public static Condition NotIn<T>(string name, params T[] values) where T : IEquatable<T>
		{
			if(values == null)
				throw new ArgumentNullException(nameof(values));

			return new Condition(name, values, ConditionOperator.NotIn);
		}

		public static Condition Exists(string name, ICondition filter = null)
		{
			return new Condition(name, filter, ConditionOperator.Exists);
		}

		public static Condition NotExists(string name, ICondition filter = null)
		{
			return new Condition(name, filter, ConditionOperator.NotExists);
		}
		#endregion

		#region 符号重写
		public static ConditionCollection operator &(Condition a, Condition b)
		{
			if(a == null)
			{
				if(b == null)
					return null;
				else
					return new ConditionCollection(ConditionCombination.And, b);
			}
			else
			{
				if(b == null)
					return new ConditionCollection(ConditionCombination.And, a);
				else
					return new ConditionCollection(ConditionCombination.And, a, b);
			}
		}

		public static ConditionCollection operator |(Condition a, Condition b)
		{
			if(a == null)
			{
				if(b == null)
					return null;
				else
					return new ConditionCollection(ConditionCombination.Or, b);
			}
			else
			{
				if(b == null)
					return new ConditionCollection(ConditionCombination.Or, a);
				else
					return new ConditionCollection(ConditionCombination.Or, a, b);
			}
		}
		#endregion

		#region 重写方法
		public bool Equals(Condition other)
		{
			if(other == null)
				return false;

			return this.Operator == other.Operator &&
				object.Equals(this.Field, other.Field) &&
				object.Equals(this.Value, other.Value);
		}

		public override bool Equals(object obj)
		{
			return obj != null && this.Equals(obj as Condition);
		}

		public override int GetHashCode()
		{
			var value = this.Value;

			if(value == null)
				return HashCode.Combine(this.Operator, this.Field);
			else
				return HashCode.Combine(this.Operator, this.Field, value);
		}

		public override string ToString()
		{
			var value = this.Value;
			var text = this.GetValueText(value);

			switch(this.Operator)
			{
				case ConditionOperator.Equal:
					return this.IsNull(value) ? $"{this.Field} IS NULL" : $"{this.Field} == {text}";
				case ConditionOperator.NotEqual:
					return this.IsNull(value) ? $"{this.Field} IS NOT NULL" : $"{this.Field} != {text}";
				case ConditionOperator.GreaterThan:
					return $"{this.Field} > {text}";
				case ConditionOperator.GreaterThanEqual:
					return $"{this.Field} >= {text}";
				case ConditionOperator.LessThan:
					return $"{this.Field} < {text}";
				case ConditionOperator.LessThanEqual:
					return $"{this.Field} <= {text}";
				case ConditionOperator.Like:
					return $"{this.Field} LIKE {text}";
				case ConditionOperator.Between:
					return $"{this.Field} BETWEEN ({text})";
				case ConditionOperator.In:
					return $"{this.Field} IN [{text}]";
				case ConditionOperator.NotIn:
					return $"{this.Field} NOT IN [{text}]";
				case ConditionOperator.Exists:
					return $"{this.Field} EXISTS ({value})";
				case ConditionOperator.NotExists:
					return $"{this.Field} NOT EXISTS ({value})";
				default:
					return $"{this.Field} {this.Operator} {text}";
			}
		}
		#endregion

		#region 私有方法
		private bool IsNull(object value)
		{
			return value == null || System.Convert.IsDBNull(value);
		}

		private string GetValueText(object value)
		{
			if(this.IsNull(value))
				return "NULL";

			switch(Type.GetTypeCode(value.GetType()))
			{
				case TypeCode.Boolean:
				case TypeCode.Byte:
				case TypeCode.SByte:
				case TypeCode.Single:
				case TypeCode.Double:
				case TypeCode.Decimal:
				case TypeCode.Int16:
				case TypeCode.Int32:
				case TypeCode.Int64:
				case TypeCode.UInt16:
				case TypeCode.UInt32:
				case TypeCode.UInt64:
					return value.ToString();
				case TypeCode.Char:
					return "'" + value.ToString() + "'";
				case TypeCode.String:
					return "\"" + value.ToString() + "\"";
			}

			if(value is IEnumerable enumerable)
			{
				var text = new StringBuilder();

				foreach(var item in enumerable)
				{
					if(text.Length > 0)
						text.Append(", ");

					text.Append(this.GetValueText(item));
				}

				return text.ToString();
			}

			return value.ToString();
		}
		#endregion

		#region 显式实现
		bool ICondition.Contains(string name)
		{
			return this.Field is Operand.FieldOperand field && string.Equals(name, field.Name, StringComparison.OrdinalIgnoreCase);
		}

		Condition ICondition.Find(string name)
		{
			return this.Field is Operand.FieldOperand field && string.Equals(name, field.Name, StringComparison.OrdinalIgnoreCase) ? this : null;
		}

		Condition[] ICondition.FindAll(string name)
		{
			return this.Field is Operand.FieldOperand field && string.Equals(name, field.Name, StringComparison.OrdinalIgnoreCase) ? new[] { this } : Array.Empty<Condition>();
		}

		bool ICondition.Match(string name, Action<Condition> matched)
		{
			if(this.Field is Operand.FieldOperand field && string.Equals(name, field.Name, StringComparison.OrdinalIgnoreCase))
			{
				matched?.Invoke(this);
				return true;
			}

			return false;
		}

		int ICondition.Matches(string name, Action<Condition> matched)
		{
			if(this.Field is Operand.FieldOperand field && string.Equals(name, field.Name, StringComparison.OrdinalIgnoreCase))
			{
				matched?.Invoke(this);
				return 1;
			}

			return 0;
		}
		#endregion

		#region 嵌套子类
		public class Builder<T>
		{
			#region 构造函数
			protected Builder()
			{
			}
			#endregion

			#region 文本版本
			public static Condition Equal(string name, object value)
			{
				return Condition.Equal(name, value);
			}

			public static Condition Equal(string name, Operand value)
			{
				return Condition.Equal(name, value);
			}

			public static Condition Equal(Operand field, Operand value)
			{
				return Condition.Equal(field, value);
			}

			public static Condition NotEqual(string name, object value)
			{
				return Condition.NotEqual(name, value);
			}

			public static Condition NotEqual(string name, Operand value)
			{
				return Condition.NotEqual(name, value);
			}

			public static Condition NotEqual(Operand field, Operand value)
			{
				return Condition.NotEqual(field, value);
			}

			public static Condition GreaterThan(string name, object value)
			{
				return Condition.GreaterThan(name, value);
			}

			public static Condition GreaterThan(string name, Operand value)
			{
				return Condition.GreaterThan(name, value);
			}

			public static Condition GreaterThan(Operand field, Operand value)
			{
				return Condition.GreaterThan(field, value);
			}

			public static Condition GreaterThanEqual(string name, object value)
			{
				return Condition.GreaterThanEqual(name, value);
			}

			public static Condition GreaterThanEqual(string name, Operand value)
			{
				return Condition.GreaterThanEqual(name, value);
			}

			public static Condition GreaterThanEqual(Operand field, Operand value)
			{
				return Condition.GreaterThanEqual(field, value);
			}

			public static Condition LessThan(string name, object value)
			{
				return Condition.LessThan(name, value);
			}

			public static Condition LessThan(string name, Operand value)
			{
				return Condition.LessThan(name, value);
			}

			public static Condition LessThan(Operand field, Operand value)
			{
				return Condition.LessThan(field, value);
			}

			public static Condition LessThanEqual(string name, object value)
			{
				return Condition.LessThanEqual(name, value);
			}

			public static Condition LessThanEqual(string name, Operand value)
			{
				return Condition.LessThanEqual(name, value);
			}

			public static Condition LessThanEqual(Operand field, Operand value)
			{
				return Condition.LessThanEqual(field, value);
			}

			public static Condition Like(string name, string value)
			{
				return Condition.Like(name, value);
			}

			public static Condition Like(Operand field, string value)
			{
				return Condition.Like(field, value);
			}

			public static Condition Between<TValue>(string name, Range<TValue> range) where TValue : struct, IComparable<TValue>
			{
				return Condition.Between<TValue>(name, range);
			}

			public static Condition Between<TValue>(string name, TValue minimum, TValue maximum) where TValue : struct, IComparable<TValue>
			{
				return Condition.Between<TValue>(name, minimum, maximum);
			}

			public static Condition Between<TValue>(string name, TValue? minimum, TValue? maximum) where TValue : struct, IComparable<TValue>
			{
				return Condition.Between<TValue>(name, minimum, maximum);
			}

			public static Condition In<TValue>(string name, IEnumerable<TValue> values) where TValue : IEquatable<TValue>
			{
				return Condition.In<TValue>(name, values);
			}

			public static Condition In<TValue>(string name, params TValue[] values) where TValue : IEquatable<TValue>
			{
				return Condition.In<TValue>(name, values);
			}

			public static Condition NotIn<TValue>(string name, IEnumerable<TValue> values) where TValue : IEquatable<TValue>
			{
				return Condition.NotIn<TValue>(name, values);
			}

			public static Condition NotIn<TValue>(string name, params TValue[] values) where TValue : IEquatable<TValue>
			{
				return Condition.NotIn<TValue>(name, values);
			}

			public static Condition Exists(string name, ICondition filter = null)
			{
				return Condition.Exists(name, filter);
			}

			public static Condition NotExists(string name, ICondition filter = null)
			{
				return Condition.NotExists(name, filter);
			}
			#endregion

			#region 表达式版本
			public static Condition Equal<TValue>(Expression<Func<T, TValue>> member, TValue value)
			{
				return Condition.Equal(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition NotEqual<TValue>(Expression<Func<T, TValue>> member, TValue value)
			{
				return Condition.NotEqual(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition GreaterThan<TValue>(Expression<Func<T, TValue>> member, TValue value)
			{
				return Condition.GreaterThan(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition GreaterThanEqual<TValue>(Expression<Func<T, TValue>> member, TValue value)
			{
				return Condition.GreaterThanEqual(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition LessThan<TValue>(Expression<Func<T, TValue>> member, TValue value)
			{
				return Condition.LessThan(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition LessThanEqual<TValue>(Expression<Func<T, TValue>> member, TValue value)
			{
				return Condition.LessThanEqual(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition Like(Expression<Func<T, string>> member, string value)
			{
				return Condition.Like(Reflection.ExpressionUtility.GetMemberName(member), value);
			}

			public static Condition Between<TValue>(Expression<Func<T, TValue>> member, Range<TValue> range) where TValue : struct, IComparable<TValue>
			{
				return Condition.Between<TValue>(Reflection.ExpressionUtility.GetMemberName(member), range);
			}

			public static Condition Between<TValue>(Expression<Func<T, TValue>> member, TValue minimum, TValue maximum) where TValue : struct, IComparable<TValue>
			{
				return Condition.Between(Reflection.ExpressionUtility.GetMemberName(member), minimum, maximum);
			}

			public static Condition Between<TValue>(Expression<Func<T, TValue>> member, TValue? minimum, TValue? maximum) where TValue : struct, IComparable<TValue>
			{
				return Condition.Between(Reflection.ExpressionUtility.GetMemberName(member), minimum, maximum);
			}

			public static Condition In<TValue>(Expression<Func<T, TValue>> member, params TValue[] values) where TValue : IEquatable<TValue>
			{
				return Condition.In(Reflection.ExpressionUtility.GetMemberName(member), values);
			}

			public static Condition In<TValue>(Expression<Func<T, TValue>> member, IEnumerable<TValue> values) where TValue : IEquatable<TValue>
			{
				return Condition.In(Reflection.ExpressionUtility.GetMemberName(member), values);
			}

			public static Condition NotIn<TValue>(Expression<Func<T, TValue>> member, params TValue[] values) where TValue : IEquatable<TValue>
			{
				return Condition.NotIn(Reflection.ExpressionUtility.GetMemberName(member), values);
			}

			public static Condition NotIn<TValue>(Expression<Func<T, TValue>> member, IEnumerable<TValue> values) where TValue : IEquatable<TValue>
			{
				return Condition.NotIn(Reflection.ExpressionUtility.GetMemberName(member), values);
			}
			#endregion
		}
		#endregion
	}
}
