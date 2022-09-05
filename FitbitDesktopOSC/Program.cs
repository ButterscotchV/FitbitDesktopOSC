using System.Diagnostics;
using System.Runtime.InteropServices;
using FitbitDesktopOSC;

using var scanner = new MemoryScanner("Fitbit");

Console.WriteLine("Scanning memory...");
var stopwatch = new Stopwatch();
stopwatch.Start();
//scanner.ScanMemoryEnsureEndianness(60d, true);
scanner.ScanMemory("H");
stopwatch.Stop();
Console.WriteLine($"Done scanning memory! Took {stopwatch.Elapsed}");
Console.WriteLine($"Found {scanner.GetTargetPointers().Length} targets!");

Console.WriteLine("Filtering pointers...");
stopwatch.Restart();
//scanner.FilterPointersEnsureEndianness(22d, true);
scanner.FilterPointers("He");
stopwatch.Stop();
Console.WriteLine($"Done scanning memory! Took {stopwatch.Elapsed}");
Console.WriteLine($"Found {scanner.GetTargetPointers().Length} targets!");

Console.WriteLine("Filtering pointers...");
stopwatch.Restart();
//scanner.FilterPointersEnsureEndianness(89d, true);
scanner.FilterPointers("Heart");
stopwatch.Stop();
Console.WriteLine($"Done scanning memory! Took {stopwatch.Elapsed}");
Console.WriteLine($"Found {scanner.GetTargetPointers().Length} targets!");

Console.WriteLine("Filtering pointers...");
stopwatch.Restart();
//scanner.FilterPointersEnsureEndianness(12d, true);
scanner.FilterPointers("HeartRate");
stopwatch.Stop();
Console.WriteLine($"Done scanning memory! Took {stopwatch.Elapsed}");
Console.WriteLine($"Found {scanner.GetTargetPointers().Length} targets!");

/*
while (true)
{
    // Read doubles back
    foreach (var pointer in scanner.GetTargetPointers())
    {
        Console.WriteLine(BitConverter.ToDouble(MemoryScanner.EnsureEndiannessFrom(scanner.ReadPointer(pointer, sizeof(double), out _), true)));
    }

    Console.ReadLine();
}
*/
