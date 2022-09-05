using System.Diagnostics;
using System.Text;
using FitbitDesktopOSC;

using var scanner = new MemoryScanner("Fitbit");
Console.WriteLine("Scanning memory...");
var stopwatch = new Stopwatch();
stopwatch.Start();
scanner.ScanMemory(Encoding.UTF8.GetBytes("HeartRate"));
stopwatch.Stop();
Console.WriteLine($"Done scanning memory! Took {stopwatch.Elapsed.ToString()}");

Console.WriteLine($"Found {scanner.GetTargetPointers().Length} targets!");
