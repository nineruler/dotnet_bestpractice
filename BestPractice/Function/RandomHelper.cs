using System;
using System.Linq;

namespace BestPractice.Function
{
    public class RandomHelper
    {
        public static string GetRandomKeyCode(int length, bool onlyNumber = false)
        {
            Random rand = new Random();

            string input = "abcdefghijklmnopqrstuvwxyz0123456789";

            if (onlyNumber)
                input = "0123456789";

            var chars = Enumerable.Range(0, length).Select(x => input[rand.Next(0, input.Length)]);

            return new string(chars.ToArray());
        }
    }
}
