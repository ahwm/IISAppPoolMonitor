using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AppPoolMonitor
{
    internal static class Extensions
    {
        public static string ToHex(this byte[] ba)
        {
            var hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            return hex.ToString();
        }

        public static string[] Trim(this string[] val)
        {
            List<string> l = val.ToList();
            for (int i = 0; i < l.Count; i++)
                l[i] = l[i].Trim();

            return l.ToArray();
        }
    }
}
