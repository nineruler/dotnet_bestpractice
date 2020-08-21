using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BestPractice
{
    /// <summary>
    /// Unix Timestamp
    /// 서버/클라이언트 통신 시에 사용
    /// DateTime을 String으로 변환하여 전달할 경우
    /// 언어/환경에 따라 형변환이 어려울 수 있기 때문
    /// 단위는 초(sec)를 많이 사용
    /// </summary>
    public class Unixtimestamp
    {
        /// <summary>
        /// DateTime -> Unix Timestamp Seconds(long)
        /// </summary>
        /// <param name="datetime"></param>
        /// <returns></returns>
        public static long FromDateTime(DateTime datetime)
        {
            return ((DateTimeOffset)datetime).ToUnixTimeSeconds();
        }

        /// <summary>
        /// Unix Timestamp Seconds(long) -> DateTime
        /// </summary>
        /// <param name="timestamp"></param>
        /// <returns></returns>
        public static DateTime FromUnixTimeSeconds(long timestamp)
        {
            return (DateTimeOffset.FromUnixTimeSeconds(timestamp)).DateTime;
        }
    }
}
