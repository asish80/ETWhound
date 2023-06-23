using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Security.Principal;
using System.Reflection;
//using Wireshark;
using System.Runtime.InteropServices;
using System.Collections;
using System.Linq;
using System.Threading.Tasks;
using System.Management;
using Newtonsoft.Json;
using System.Net;

using static ETWHound.TDevMonitor;
using System.Xml.Linq;
using static ETWHound.Program;
using System.Runtime.InteropServices.ComTypes;

namespace ETWHound
{
    public class NamedPipeSniffer
    {
        //private WiresharkSender wiresharkSender;
        //private ChromeMonitor chromeMonitor;
  
        string pipeNameFilter = "";
        private bool recordingOnlyNewMojoPipes;

        // Tibbo Device Monitor buffering
        private TDevMonitor tdevMonitor;
        private int BLOCK_SIZE = 4096;
        private StreamReader tdevStream;
        private bool useExtraStreamBuffering = false;
        private QueueStream tdevBufferedStream;
        private bool isShuttingDown = false;

        // simulated stream (for debugging)
        private bool useSimulatedStream = false;
        private bool recordStream = false;
        private StreamWriter replayStreamWriter;

        // statistics
        private int numPacketsProcessed = 0;
        private DateTime lastDropTime;

        Dictionary<string, NamedPipeInfo> namedPipeFiles;
        List<string> destoryedNamedPipes;


        public class TrackNamedPipe
        {

            public string Name { get; set; }
            public Guid NodeId { get; set; }

            public UInt64 FileObjectIdentifier;

            public UInt32 SourceProcessId;

            public UInt32 DestProcessId;

            public UInt32 AccessCount;




            public TrackNamedPipe(string name,UInt32 pid1, UInt32 pid2)
            {
                this.Name = name;
                this.SourceProcessId = pid1;
                this.DestProcessId = pid2;
                this.NodeId = Program.GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();

            }


            public bool FoundNamedPipe(string name)
            {

                if (this.Name == name)
                    return true;
                else
                    return false;

            }


            public Guid searchNamedPipe(string cuser)
            {
                if (this.Name == cuser)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }
        }


        public NamedPipeSniffer(string wiresharkPipeName, string nameFilter = "", bool recordOnlyNewMojoPipes = false)
        {
           // this.wiresharkSender = new WiresharkSender(wiresharkPipeName, 1);
            this.namedPipeFiles = new Dictionary<string, NamedPipeInfo>();
            this.destoryedNamedPipes = new List<string>();
           // this.chromeMonitor = chromeMonitor;
            this.recordingOnlyNewMojoPipes = recordOnlyNewMojoPipes;
            this.pipeNameFilter = nameFilter;
            this.lastDropTime = DateTime.Now;
            this.numPacketsProcessed = 0;
        }

        /// <summary>
        /// Starts the pipe monitoring capability using Tibbo driver,
        /// as well as the processing/consuming loop
        /// </summary>
        /// <returns></returns>
        public bool Start()
        {
            //bool isElevated = ElevationUtils.HasAdminRights();
            //if (!isElevated)
          //  {
           //     Console.WriteLine("[-] Admin privileges is needed to use the sniffing driver.");
             //   return false;
         //   }

            this.tdevMonitor = new TDevMonitor();

            if (useSimulatedStream)
            {
                Console.WriteLine("[+] Re-playing previously recorded packets stream.");
                this.tdevStream = new StreamReader(new FileStream(@"last_tdevmon_stream.bin", FileMode.Open));
            }
            else
            {
                this.tdevStream = this.tdevMonitor.StartMonitoringDevice(@"\Device\NamedPipe", this.recordingOnlyNewMojoPipes ? "*mojo*" : "");
            }

            if (recordStream)
            {
                replayStreamWriter = new StreamWriter(new FileStream("last_tdevmon_stream.bin", FileMode.Create));
            }

            if (useExtraStreamBuffering)
            {
                this.tdevBufferedStream = new QueueStream();
                Thread readingLoopThread = new Thread(new ThreadStart(ExtraBufferingReadingLoop));
                readingLoopThread.Start();
            }

            Thread processingLoopThread = new Thread(new ThreadStart(ProcessingLoop)) { Priority = ThreadPriority.AboveNormal };
            processingLoopThread.Start();

           Thread statisticsThread = new Thread(new ThreadStart(StatisticsThread));
           statisticsThread.Start();

            return true;
        }


        public void finish()
        {

           /* foreach (var kvp in namedPipeFiles)
            {
                Console.WriteLine("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            }
           */
         
        }

        private void StatisticsThread()
        {
            Thread.Sleep(1000);

            var startTimeSpan = TimeSpan.Zero;
            var periodTimeSpan = TimeSpan.FromSeconds(0.3);

            while (!isShuttingDown)
            {
                Thread.Sleep((int)periodTimeSpan.TotalMilliseconds);
                int packetsPerSecond = (int)((double)this.numPacketsProcessed / periodTimeSpan.TotalSeconds);

                Console.SetCursorPosition(0, Console.CursorTop - 1);
                Console.WriteLine("[+] Capturing " + packetsPerSecond + " packets/second...\n");

                this.numPacketsProcessed = 0;
            }
        }

        /// <summary>
        /// Continiously reads notification data from the kernel driver/buffering stream
        /// and heads it over to ProcessNotification
        /// </summary>
        public void ProcessingLoop()
        {
            BinaryReader sourceTdevStream = useExtraStreamBuffering ? new BinaryReader(this.tdevBufferedStream) :
                                                                   new BinaryReader(this.tdevStream.BaseStream);

            Stopwatch totalStopwatch = new Stopwatch();
            totalStopwatch.Start();

            long streamPosition = 0;
            double timePeek = 0;

            BinaryReader packetsReader;

            try
            {

                while (!isShuttingDown)
                {
                    if (this.tdevBufferedStream != null) this.tdevBufferedStream.OnDataAvailable.WaitOne();

                    // Read the next bunch of packets
                    packetsReader = new BinaryReader(new MemoryStream());
                    AppendToStream(sourceTdevStream.BaseStream, packetsReader.BaseStream, BLOCK_SIZE);

                    Stopwatch sw = new Stopwatch();
                    sw.Start();

                    while (packetsReader.BaseStream.Position < packetsReader.BaseStream.Length)
                    {
                        long headerEndOffset = packetsReader.BaseStream.Position + Marshal.SizeOf(typeof(dm_NotifyHdr));
                        if (packetsReader.BaseStream.Length < headerEndOffset &&
                            tdevMonitor.ReadMode == dm_ReadMode.dm_ReadMode_Stream)
                        {
                            // We need to read more data so the notification header could be read completely
                            long missingSize = headerEndOffset - packetsReader.BaseStream.Length;
                            AppendToStream(sourceTdevStream.BaseStream, packetsReader.BaseStream, missingSize, true);
                        }

                        dm_NotifyHdr notificationHeader = packetsReader.ReadStruct<dm_NotifyHdr>();
                        if (notificationHeader.signature != 1852796276)
                        {
                            throw new Exception("Encountered bad signature (" + notificationHeader.signature + ") at position "
                                + (streamPosition + packetsReader.BaseStream.Position) + "!");
                        }

                        long notificationParamBeginOffset = packetsReader.BaseStream.Position;

                        if ((notificationHeader.flags & (ushort)dm_NotifyFlag.dm_NotifyFlag_InsufficientBuffer) > 0)
                        {
                            BLOCK_SIZE *= 2;
                            Console.WriteLine("[-] Buffer was not sufficient, increasing block size to " + BLOCK_SIZE);

                            // skip this packet
                            long remainingSize1 = (notificationParamBeginOffset + notificationHeader.paramSize) - packetsReader.BaseStream.Position;
                            packetsReader.ReadBytes((int)remainingSize1);
                            break;
                        }

                        if ((notificationHeader.flags & (ushort)dm_NotifyFlag.dm_NotifyFlag_DataDropped) > 0)
                        {
                            TimeSpan timeFromLastDrop = DateTime.Now - this.lastDropTime;

                            if (timeFromLastDrop.TotalMilliseconds > 700)
                                Console.WriteLine("[-] Some packets were dropped.");

                            lastDropTime = DateTime.Now;
                        }

                        long paramsEndOffset = notificationParamBeginOffset + notificationHeader.paramSize;
                        if (packetsReader.BaseStream.Length < paramsEndOffset &&
                            tdevMonitor.ReadMode == dm_ReadMode.dm_ReadMode_Stream)
                        {
                            // We need to read more data so the packet could be read completely
                            long missingSize = paramsEndOffset - packetsReader.BaseStream.Length;
                            AppendToStream(sourceTdevStream.BaseStream, packetsReader.BaseStream, missingSize, true);
                        }

                        ProcessNotification(notificationHeader, packetsReader);

                        long remainingSize = (notificationParamBeginOffset + notificationHeader.paramSize) - packetsReader.BaseStream.Position;
                        byte[] read = packetsReader.ReadBytes((int)remainingSize);
                    }

                    sw.Stop();
                    if (sw.Elapsed.TotalMilliseconds > timePeek) timePeek = sw.Elapsed.TotalMilliseconds;

                    streamPosition += packetsReader.BaseStream.Position;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void ProcessNotification(dm_NotifyHdr notificationHeader, BinaryReader paramsReader)
        {
            dm_NotifyCode notificationType = (dm_NotifyCode)notificationHeader.code;

            switch (notificationType)
            {
                case dm_NotifyCode.dm_NotifyCode_Write:
                case dm_NotifyCode.dm_NotifyCode_Read:
                case dm_NotifyCode.dm_NotifyCode_FastIoRead:
                case dm_NotifyCode.dm_NotifyCode_FastIoWrite:

                    var writeParams = paramsReader.ReadStruct<dm_ReadWriteNotifyParams>();
                    long remainingParamSize = notificationHeader.paramSize - Marshal.SizeOf(typeof(dm_ReadWriteNotifyParams));
                    if (writeParams.dataSize > remainingParamSize)
                    {
                        // TODO: Remember this packet and expect its continued packet

                        Console.WriteLine("[!] Truncated packet.");
                    }

                    int dataSize = (int)Math.Min(writeParams.dataSize, remainingParamSize);
                    byte[] data = paramsReader.ReadBytes(dataSize);

                    OnReadWritePacketReceived(notificationHeader, writeParams, data, notificationType == dm_NotifyCode.dm_NotifyCode_Write);

                    break;
                case dm_NotifyCode.dm_NotifyCode_Create:
                case dm_NotifyCode.dm_NotifyCode_CreateNamedPipe:

                    dm_CreateNotifyParams createParams = notificationType == dm_NotifyCode.dm_NotifyCode_CreateNamedPipe ?
                        paramsReader.ReadStruct<dm_CreateNamedPipeNotifyParams>().createParams : paramsReader.ReadStruct<dm_CreateNotifyParams>();

                    int pipeFileNameLength = (int)createParams.fileNameLength * 2;
                    string pipeName = Encoding.Unicode.GetString(paramsReader.ReadBytes(pipeFileNameLength));
                    paramsReader.ReadUInt16(); // read the NULL-terminate

                    OnCreatePacketReceived(notificationHeader, createParams, pipeName);

                    break;
                case dm_NotifyCode.dm_NotifyCode_Close:

                    dm_CloseNotifyParams closeParams = paramsReader.ReadStruct<dm_CloseNotifyParams>();
                    OnClosePacketReceived(notificationHeader, closeParams);

                    break;
            }

            if (useExtraStreamBuffering)
            {
                long catchUp = tdevBufferedStream.WritePosition - tdevBufferedStream.ReadPosition;
                //if (catchUp > 1000)
                //    Console.WriteLine("Position catch-up: {0}", catchUp);
            }

        }

        public void OnCreatePacketReceived(dm_NotifyHdr notificationHeader, dm_CreateNotifyParams createParams, string pipeName)
        {
            UInt64 pipeFileIdentifier = createParams.fileIdentifier;

            List<NamedPipeInfo> matchingPipes = namedPipeFiles.Values.Where((x) => x.FileObjects.Contains(pipeFileIdentifier)).ToList();
            if (matchingPipes.Count >= 1)
            {
                // Opening a new file with an already-existing file object? The previous file object must be dead.
                namedPipeFiles.Remove(matchingPipes[0].PipeFileName);
            }

            if (!namedPipeFiles.ContainsKey(pipeName))
            {
                // Create a new pipe
                namedPipeFiles[pipeName] = new NamedPipeInfo(pipeFileIdentifier, pipeName, notificationHeader.processId);

            //    chromeMonitor.UpdateRunningProcessesCache();
            }
            else
            {
                // We already know this pipe, it must be another process that opens a new handle to it
                namedPipeFiles[pipeName].AddFileObjectIfNeeded(pipeFileIdentifier);
                namedPipeFiles[pipeName].AddProcessIfNeeded(notificationHeader.processId);
            }

           

           

        }

        public void OnClosePacketReceived(dm_NotifyHdr notificationHeader, dm_CloseNotifyParams closeParams)
        {
            UInt64 fileID = closeParams.fileId;
            List<NamedPipeInfo> matchingPipes = namedPipeFiles.Values.Where((x) => x.FileObjects.Contains(fileID)).ToList();
            if (matchingPipes.Count != 1 && recordingOnlyNewMojoPipes)
            {
                throw new Exception("I will not suffer inconcicentcies.");
            }

            if (matchingPipes.Count == 1)
                matchingPipes[0].FileObjects.Remove(fileID);
        }

        public static Process[] GetRunningChromeProcesses()
        {
            return Process.GetProcessesByName("chrome");
        }

        public void OnReadWritePacketReceived(dm_NotifyHdr notificationHeader, dm_ReadWriteNotifyParams writeParams, byte[] data, bool isWriting)
        {
            UInt64 fileObject = writeParams.fileIdentifier;
            UInt32 processId = notificationHeader.processId;

           // if (!chromeMonitor.IsChromeProcess(processId)) return;

            // Find out on which pipe this packet was sent
            NamedPipeInfo pipe = DeterminePipeFromPacket(notificationHeader, writeParams);
            string pipeName = pipe != null ? pipe.PipeFileName : "<Unknown " + fileObject.ToString("X") + ">";

            if (pipe != null)
            {
                // Update this pipe's information
                namedPipeFiles[pipeName].AddProcessIfNeeded(processId);
                namedPipeFiles[pipeName].AddFileObjectIfNeeded(fileObject);
            }

            if (!pipeName.Contains(this.pipeNameFilter)) return;

            //
            // Find out what is the destination process of this packet
            //
            UInt32 destinationPID = 0;
            if (pipe != null)
            {
                if (pipe.InvolvedProcesses.Count < 2 && !destoryedNamedPipes.Contains(pipe.PipeFileName))
                {
                    //
                    // try to find the destination process using Windows handle query
                    //

                    List<int> legalPIDs = GetRunningChromeProcesses().Select(process => process.Id).ToList();
                    string fullPipePath = @"\Device\NamedPipe" + pipe.PipeFileName;
                    namedPipeFiles[pipeName].InvolvedProcesses = HandlesUtility.GetProcessesUsingFile(fullPipePath, legalPIDs);
                    if (namedPipeFiles[pipeName].InvolvedProcesses.Count < 2)
                    {
                        // TODO: because we are doing heavy caching on the handle information, 
                        // it happens sometimes that we reach here but the pipe actually is in fact valid.
                        //Console.WriteLine("[-] Could not find destination PID for " + pipeName);
                        destoryedNamedPipes.Add(pipe.PipeFileName);
                    }

                }

                if (pipe.InvolvedProcesses.Count >= 2)
                {
                    List<uint> involvedProcesses = pipe.InvolvedProcesses.ToList();
                    involvedProcesses.Remove(notificationHeader.processId);
                    destinationPID = involvedProcesses.Last();
                }
            }

            if (!isWriting) return;
            if (data.Length == 0) return;

            /*
            Console.WriteLine("On Read write packet received");
            Console.WriteLine(pipeName);
            Console.WriteLine(destinationPID);
            */
            //
            // Send it off
            //
            this.numPacketsProcessed++;
            byte[] wiresharkPacket = GenerateWiresharkPacket(notificationHeader, writeParams, pipeName, destinationPID, data);
            //wiresharkSender.SendToWiresharkAsEthernet(wiresharkPacket, 0);

        }

        public NamedPipeInfo DeterminePipeFromPacket(dm_NotifyHdr notificationHeader, dm_ReadWriteNotifyParams writeParams)
        {
            UInt64 fileObject = writeParams.fileIdentifier;

            // Search for the pipe by the file object
            List<NamedPipeInfo> matchingPipes = namedPipeFiles.Values.Where((x) => x.FileObjects.Contains(fileObject)).ToList();
            if (matchingPipes.Count == 1) return matchingPipes[0];

            if (destoryedNamedPipes.Contains(fileObject.ToString("X"))) return null;

            if (matchingPipes.Count == 0)
            {
                // We didn't see this file object before.

                if (this.recordingOnlyNewMojoPipes)
                {
                    // are we missing create packets?
                    // we probably do, because we can't read fast enough.
                    throw new Exception("I will not suffer inconsistencies.");
                }

                //Console.WriteLine(fileObject);
                //
                // Try to get the pipe name from the file object
                //
                string pipeName = HandlesUtility.GetFilePathFromFileObject(new IntPtr((long)fileObject));
                if (pipeName != null && pipeName.Contains(@"\Device\NamedPipe"))
                {
                    pipeName = pipeName.Substring(@"\Device\NamedPipe".Length);

                    if (!namedPipeFiles.ContainsKey(pipeName))
                    {
                        // We don't know this pipe
                        // create it then

                        namedPipeFiles[pipeName] = new NamedPipeInfo(fileObject, pipeName, notificationHeader.processId);
                    }

                    return namedPipeFiles[pipeName];
                }
                else
                {
                    // either the pipe does not exist anymore, or its handle was closed, or NtQueryObject got hang
                }
            }
            else
            {
                // this file object must be dead, because it's used in two pipes
                throw new Exception("I will not suffer inconsistencies.");
            }

            //Console.WriteLine("[-] Could not find pipe name for " + fileObject.ToString("X"));
            destoryedNamedPipes.Add(fileObject.ToString("X"));
            return null;
        }

        // This should be updated whenever a chrome process gets created/destryoed
        private Dictionary<UInt32, ProcessInfo> RunningProcessesCache = new Dictionary<UInt32, ProcessInfo>();

        public string DLLPath = string.Empty;
        public string ChromeVersion = string.Empty;


        private bool ProcessExists(UInt32 pid)
        {
            UpdateRunningProcessesCache();

            return RunningProcessesCache.ContainsKey(pid);
        }

        public void UpdateRunningProcessesCache()
        {
            Process[] runningProcesses = Process.GetProcesses();
            foreach (Process process in runningProcesses)
            {
                ProcessInfo processInfo;
                processInfo.PID = process.Id;
                processInfo.Name = process.ProcessName;
                processInfo.CommandLine = processInfo.Name == "chrome" ? process.GetCommandLine() : "";
                RunningProcessesCache[(UInt32)process.Id] = processInfo;
            }
        }

    
        public struct ProcessInfo
        {
            public string Name;
            public int PID;
            public string CommandLine;
        }

        public ChromeProcessType GetChromeProcessType(UInt32 chromePID)
        {
            string commandLine = null;
            string processName = null;

            UpdateRunningProcessesCache();

            if (RunningProcessesCache.ContainsKey(chromePID))
            {
                commandLine = RunningProcessesCache[chromePID].CommandLine;
                processName = RunningProcessesCache[chromePID].Name;
            }
            else
            {
                return ChromeProcessType.Unknown;
            }

            ChromeProcessType type = ChromeProcessType.Unknown;

            // Some sanity checks
            if (processName != "chrome") return type;
            if (commandLine == null) return type;

            if (!commandLine.Contains("--type=")) type = ChromeProcessType.Broker;
            else if (commandLine.Contains("--extension-process") && !commandLine.Contains("--disable-databases")) type = ChromeProcessType.Extension;
            else if (commandLine.Contains("--type=watcher")) type = ChromeProcessType.Watcher;
            else if (commandLine.Contains("--utility-sub-type=audio.mojom.AudioService")) type = ChromeProcessType.AudioService;
            else if (commandLine.Contains("--utility-sub-type=network.mojom.NetworkService")) type = ChromeProcessType.NetworkService;
            else if (commandLine.Contains("--service-sandbox-type=cdm")) type = ChromeProcessType.ContentDecryptionModuleService;
            else if (commandLine.Contains("--type=gpu-process")) type = ChromeProcessType.GpuProcess;
            else if (commandLine.Contains("--type=renderer")) type = ChromeProcessType.Renderer;

            return type;
        }

       

        public enum ChromeProcessType
        {
            Unknown = 0,
            Broker,
            Renderer,
            Extension,
            Notification,
            Plugin,
            Worker,
            NCAL,
            GpuProcess,
            Watcher,
            ServiceWorker,
            NetworkService,
            AudioService,
            ContentDecryptionModuleService,
            CrashpadHandler,
            PpapiBroker,
        }
        public byte[] GenerateWiresharkPacket(TDevMonitor.dm_NotifyHdr header, TDevMonitor.dm_ReadWriteNotifyParams writeParams,
                                              string pipeName, UInt32 destPID, byte[] data)
        {
            MemoryStream memoryStream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(memoryStream);

            UInt32 sourcePID = header.processId;
            string prdata = string.Empty;
            string ppdata = string.Empty;

            writer.Write(header.code);
            writer.Write(sourcePID);
            writer.Write(destPID);
            writer.Write((UInt32)GetChromeProcessType(sourcePID));
            writer.Write((UInt32)GetChromeProcessType(destPID));
            writer.Write(header.threadId);
            writer.Write(pipeName);
            writer.Write(header.timestamp);
            writer.Write(writeParams.dataSize);
            

            bool CfoundNamedPipe = false;
            Guid CfoundNamedNodeId = Guid.Empty;


            foreach (TrackNamedPipe iNamed in Program.mydata.CNamedPipes)
            {
               /// Console.WriteLine(pipeName);
                //Console.WriteLine(iNamed.Name);
                if (iNamed.FoundNamedPipe(pipeName))
                {
                    CfoundNamedPipe = true;
                    CfoundNamedNodeId = iNamed.searchNamedPipe(pipeName);
                }
            }

            if (CfoundNamedPipe == false)
            {
                //Console.WriteLine("Npipe not found");
                //ShareNames cshare = new ShareNames(data, connguid);
                TrackNamedPipe cNamed = new TrackNamedPipe(pipeName,sourcePID,destPID);

                Program.mydata.CNamedPipes.Add(cNamed);

                Program.Relationship trelation1 = new Program.Relationship(Program.startingGlobalNodeId,cNamed.NodeId, "ReadWrite", "Computer", "NamedPipe");
                Program.mydata.Relationships.Add(trelation1);

                try
                {
                    var p = Process.GetProcessById((int)sourcePID);
                    prdata =  p.MainModule.FileName.ToLower(); ;
                }
                catch
                {
                    prdata = "Not running process";
                }
                try
                {
                    var p = Process.GetProcessById((int)destPID);
                    ppdata = p.MainModule.FileName.ToLower(); ;
                }
                catch
                {
                    ppdata = "Not running process";
                }

               // Console.WriteLine("namedops :  " + prdata + " destinatio PID " + ppdata);
              
                Guid foundinameid = Guid.Empty;
                Guid foundpinameid = Guid.Empty;


                
                if (sourcePID != 0)
                {
                    //foundinameid = myprocess4j.process_dict[prdata];
                    
                    foreach (CProcessId prid in mydata.xImageName)
                    {
                        if (prid.foundCIprocessName(prdata))
                        {
                            //foundiname = true;
                            foundinameid = prid.NodeId;
                            prid.NodeCnt++;
                            break;
                            //  foundinameid = prid.searchCIprocessName(data); 
                        }
                    }
                }

               // Console.WriteLine("foundinameid :  " + foundinameid.ToString());

                if (destPID != 0)
                {
                    //foundpinameid = myprocess4j.process_dict[ppdata];

                    
                    foreach (CProcessId prid in mydata.xImageName)
                    {
                        if (prid.foundCIprocessName(ppdata))
                        {
                            //foundpiname = true;
                            foundpinameid = prid.NodeId;
                            prid.NodeCnt++;
                            break;
                            //  foundinameid = prid.searchCIprocessName(data); 
                        }
                    }
                }

                //Console.WriteLine(sourcePID);
                // Console.WriteLine(foundinameid);
                //  Console.WriteLine(foundpinameid);
                // Console.WriteLine(destPID);

                if (foundinameid != Guid.Empty)
                {
                    Program.Relationship trelation2 = new Program.Relationship(foundinameid, cNamed.NodeId, "NamedOps", "ImageName", "NamedPipe");
                    Program.mydata.Relationships.Add(trelation2);

                   // Console.WriteLine("relationship namedops");
                }

                if (foundpinameid != Guid.Empty)
                {
                    Program.Relationship trelation3 = new Program.Relationship(cNamed.NodeId, foundpinameid, "NamedOps", "NamedPipe", "ImageName");
                    Program.mydata.Relationships.Add(trelation3);
                }

            }

            /*
            Console.WriteLine(header.code);
            Console.WriteLine(sourcePID);
            Console.WriteLine(destPID);
            Console.WriteLine(header.threadId);
            Console.WriteLine(pipeName);
            Console.WriteLine(header.timestamp);
            Console.WriteLine(writeParams.dataSize);
            */

            if (data.Length > 262144)
            {
                // if this packet is too large for Wireshark's WTAP_MAX_PACKET_SIZE_STANDARD, we'll truncate it.
                data = data.Take(262000).ToArray();
            }

            writer.Write(data);

            return memoryStream.ToArray();
        }
        

        public void Stop()
        {
            this.isShuttingDown = true;
            this.tdevMonitor.Stop();
        }

        public void ExtraBufferingReadingLoop()
        {
            BinaryReader reader = new BinaryReader(this.tdevStream.BaseStream);

            byte[] buffer = new byte[BLOCK_SIZE];
            int read;
            while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
            {
                tdevBufferedStream.Write(buffer, 0, read);
            }
        }


        public int AppendToStream(Stream sourceStream, Stream destinationStream, long count, bool atLeast = false)
        {
            int miniumReadSize = Marshal.SizeOf(typeof(dm_NotifyHdr));
            long fixedCount = Math.Max(count, miniumReadSize);

            try
            {
                byte[] buffer = new byte[fixedCount];
                int read = sourceStream.Read(buffer, 0, buffer.Length);

                if (read < count && atLeast)
                {
                    while (read < count)
                    {
                        int toRead = Math.Max(buffer.Length - read, miniumReadSize);
                        if (read + toRead > buffer.Length) Array.Resize(ref buffer, read + toRead);

                        read += sourceStream.Read(buffer, read, toRead);
                    }
                }

                long originalPosition = destinationStream.Position;
                destinationStream.Seek(0, SeekOrigin.End);
                destinationStream.Write(buffer, 0, read);
                destinationStream.Seek(originalPosition, SeekOrigin.Begin);

                if (recordStream)
                    replayStreamWriter.BaseStream.Write(buffer, 0, read);


                return read;

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return 0;
            }
        }

    }

}
