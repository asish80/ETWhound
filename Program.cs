using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Reflection;
using Newtonsoft.Json;
using O365.Security.ETW;
//using Microsoft.O365.Security.ETW;
using System.Net;
using System.Collections;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Security.Cryptography;
using static ETWHound.Program;
using System.Xml.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Management;
using System.Security.Principal;
using System.Numerics;
using Microsoft.SqlServer.Server;
using System.Net.NetworkInformation;
using System.Diagnostics.Eventing.Reader;
using Mono.Cecil;
using static System.Net.Mime.MediaTypeNames;
using System.Xml;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Policy;

namespace ETWHound
{
    public static class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool EnumExportedFunctions(IntPtr moduleHandle, IntPtr callback);

        private delegate bool EnumExportedFunctionsCallbackDelegate(IntPtr moduleName, IntPtr functionOrdinal, IntPtr functionAddress);

        private static bool EnumExportedFunctionsCallback(IntPtr moduleName, IntPtr functionOrdinal, IntPtr functionAddress)
        {
            string functionName = Marshal.PtrToStringAnsi(functionOrdinal);
            Console.WriteLine(functionName);
            return true; // Continue enumeration
        }

        static readonly object _object = new object();
        public static UInt32 totalusers = 0;
        public static Guid GlobalNodeId = Guid.NewGuid();
        public static UInt32 GlobalSourceProcessId = 0;
        public static UInt32 GlobalDestProcessId = 0;

        public static UInt32 GlobalRelationShipId = 0;
        public static Guid startingGlobalNodeId = GlobalNodeId;
        public static UInt32 shareentry=0;
        public static string shareipentry = string.Empty;

        public static String ImageLoadProcessName = String.Empty;
        public static Boolean ImageLoadientry = false;
        public static UInt32 ImageLoadProcessId = 0;
        public static Mutex mutex = new Mutex();


        public class DllFunctionsRetriever
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr GetModuleHandle(string moduleName);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool EnumExportedFunctions(IntPtr moduleHandle, IntPtr callback);

            private delegate bool EnumExportedFunctionsCallbackDelegate(IntPtr moduleName, IntPtr functionOrdinal, IntPtr functionAddress);

            private static bool EnumExportedFunctionsCallback(IntPtr moduleName, IntPtr functionOrdinal, IntPtr functionAddress)
            {
                string functionName = Marshal.PtrToStringAnsi(functionOrdinal);
                Console.WriteLine(functionName);
                return true; // Continue enumeration
            }

            public static bool IsDllFile(string filePath)
            {
                string fileExtension = Path.GetExtension(filePath);
                return string.Equals(fileExtension, ".dll", StringComparison.OrdinalIgnoreCase);
            }

        }

        public class DllTypeChecker
        {
            public static bool IsDotNetDll(string filePath)
            {
                try
                {
                    using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    {
                        using (BinaryReader reader = new BinaryReader(fs))
                        {
                            // Check for the magic number indicating a .NET assembly
                            if (reader.ReadUInt32() == 0x424A5342)
                            {
                                // Check for the PE signature offset
                                uint peOffset = reader.ReadUInt32();
                                reader.BaseStream.Seek(peOffset, SeekOrigin.Begin);

                                // Check for the PE signature
                                if (reader.ReadUInt32() == 0x00004550)
                                {
                                    // Check for the CLR header
                                    reader.BaseStream.Seek(20, SeekOrigin.Current);
                                    ushort peOptionalHeaderSize = reader.ReadUInt16();
                                    reader.BaseStream.Seek(peOptionalHeaderSize - 2, SeekOrigin.Current);

                                    // Check for the metadata signature
                                    if (reader.ReadUInt32() == 0x00004550)
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // Handle any exceptions that occur during file reading
                }

                return false;
            }

        }

        public class TDllReaderFunc
        {
            public string Name { get; set; }

            public string DLLname { get; set; }
            public Guid NodeId { get; set; }

            public UInt64 NodeCnt = 0;

            public TDllReaderFunc(string Name, string DLLname)
            {
                this.Name = Name;
                this.DLLname = DLLname;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.NodeCnt = this.NodeCnt + 1;
            }

            public Guid searchDllFunc(string iname)
            {
                if (this.Name == iname)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundDllFunc(string cuser)
            {

                if (this.DLLname == cuser)
                    return true;
                else
                    return false;
            }

        }

        public class Computer
        {

            public string Name { get; set; }
            public Guid NodeId { get; set; }

            public UInt64 NodeCnt = 0;

            public Computer(string Name)
            {
                this.Name = Name;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.NodeCnt = this.NodeCnt + 1;
            }

            public string getComputer()
            {
                return this.Name;
            }

            public Guid getNodeId()
            {
                return this.NodeId;
            }

            public Guid searchComputer(string iname)
            {
                if (this.Name == iname)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundComputer(string cuser)
            {

                if (this.Name == cuser)
                    return true;
                else
                    return false;
            }
        }



        public class CPSuspend
        {
            public UInt32 processId { get; set; }
            public Guid NodeId { get; set; }

            public UInt32 parentProcessId;

            public UInt32 SessionId;

            public String imagexname;

            public UInt64 NodeCnt = 0;

            public string dt;


            public CPSuspend(UInt32 pid, UInt32 ppid, UInt32 sid, String iname)
            {
                this.processId = pid;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.parentProcessId = ppid;
                this.SessionId = sid;
                this.imagexname = iname;
                this.NodeCnt = this.NodeCnt + 1;
                this.dt = DateTime.Now.ToString(@"MM\/dd\/yyyy h\:mm tt");

            }

            public Guid searchCIprocessId(UInt32 Id)
            {
                if (this.processId == Id)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundCIprocessId(UInt32 Id)
            {

                if (this.processId == Id)
                    return true;
                else
                    return false;
            }


            public Guid searchCIprocessName(string iname)
            {
                if (this.imagexname == iname)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundCIprocessName(string cuser)
            {

                if (this.imagexname == cuser)
                    return true;
                else
                    return false;
            }


        }
        public class CImage
        {
            public UInt32 processId { get; set; }
            public Guid NodeId { get; set; }

            public UInt32 parentProcessId;

            public UInt32 ImageChecksum;

            public String imagexload;

            public UInt64 NodeCnt = 0;

            public string dt;

            public string imagesize;
            public string imagebase;


            public CImage(UInt32 pid, UInt32 imgchecksum, String iname,String imagesize, String imagebase, UInt32 timedatestamp)
            {
                this.processId = pid;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.imagexload = iname;
                this.ImageChecksum = imgchecksum;
                this.NodeCnt = this.NodeCnt + 1;
                this.dt = timedatestamp.ToString();  // DateTime.Now.ToString(@"MM\/dd\/yyyy h\:mm tt");
                this.imagebase = imagebase;
                this.imagesize = imagesize;

            }
            public Guid searchCIprocessId(UInt32 Id)
            {
                if (this.processId == Id)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundCIprocessId(UInt32 Id)
            {

                if (this.processId == Id)
                    return true;
                else
                    return false;
            }
            public Guid searchCImageName(string iname)
            {
                if (this.imagexload == iname)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundCImageName(string cuser)
            {

                if (this.imagexload == cuser)
                    return true;
                else
                    return false;
            }

        }

        public class ConnectionInfo
        {
            public string ProcessId { get; set; }
            public string ApplicationName { get; set; }
            public string Direction { get; set; }
            public string SourceAddress { get; set; }
            public string SourcePort { get; set; }
            public string DestinationAddress { get; set; }
            public string DestinationPort { get; set; }
            public string Protocol { get; set; }
            public string InterfaceIndex { get; set; }
            public string FilterOrigin { get; set; }
            public string FilterRunTimeId { get; set; }
            public string LayerName { get; set; }
            public string LayerRunTimeId { get; set; }
            public string RemoteUserId { get; set; }
            public string RemoteMachineId { get; set; }

            public Guid NodeId { get; set; }
            public UInt64 NodeCnt = 0;

        }

        public class CProcessId
        {

            public UInt32 processId { get; set; }
            public Guid NodeId { get; set; }

            public UInt32 parentProcessId;

            public UInt32 SessionId;

            public String imagexname;

            public UInt64 NodeCnt = 0;

            public string dt;

            public String processowner = String.Empty;


            public CProcessId(UInt32 pid, UInt32 ppid, UInt32 sid, String iname, string powner)
            {
                this.processId = pid;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.parentProcessId = ppid;
                this.SessionId = sid;
                this.imagexname = iname;
                this.NodeCnt = this.NodeCnt + 1;
                this.dt = DateTime.Now.ToString(@"MM\/dd\/yyyy h\:mm tt");
                this.processowner = powner;

            }
            public  void setpowner(string powner)
            {
                this.processowner = powner;
            }
            public Guid searchCIprocessId(UInt32 Id)
            {
                if (this.processId == Id)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundCIprocessId(UInt32 Id)
            {

                if (this.processId == Id)
                    return true;
                else
                    return false;
            }


            public Guid searchCIprocessName(string iname)
            {
                if (this.imagexname == iname)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

           

            public bool foundCIprocessName(string cuser)
            {

                if (this.imagexname == cuser)
                    return true;
                else
                    return false;
            }

        }


        public class CIpAddress
        {

            public string Name { get; set; }

            public UInt32 Port { get; set; }


            public Guid NodeId { get; set; }

            public string ipconnguid = String.Empty;
            public UInt64 NodeCnt = 0;


            public CIpAddress(string ip, string x)
            {
                this.Name = ip;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.ipconnguid = x;
                this.NodeCnt = this.NodeCnt + 1;
            }

            public string getCIpAddress()
            {
                return this.Name;
            }

            public Guid getNodeId()
            {
                return this.NodeId;
            }

            public string getIpGuid()
            {
                return this.ipconnguid;
            }

            public void SetIpGuid(string x)
            {
                this.ipconnguid = x;
            }

            public bool foundIpGuid(string x)
            {
                if (this.ipconnguid == x)
                    return true;
                else
                    return false;
            }
            public Guid searchCIpAddress(string cuser)
            {
                if (this.Name == cuser)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundCIpAddress(string cuser)
            {

                if (this.Name == cuser)
                    return true;
                else
                    return false;
            }
        }

        public class WMIOperation
        {

            public string Name { get; set; }
            public Guid NodeId { get; set; }

            public string NamespaceName;

            public UInt64 NodeCnt = 0;

            public WMIOperation(string name, string namespacename)
            {
                this.Name = name;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.NamespaceName = namespacename;
                this.NodeCnt = this.NodeCnt + 1;
            }


            public Guid searchWMIOperation(string cop)
            {
                if (this.Name == cop)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundWMIOperation(string cuser)
            {

                if (this.Name == cuser)
                    return true;
                else
                    return false;
            }
        }

        public class ShareNames
        {

            public string Name { get; set; }
            public Guid NodeId { get; set; }

            public Guid shareconnguid;

            public UInt64 NodeCnt = 0;

            public ShareNames(string sharename, Guid x)
            {
                this.Name = sharename;
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.shareconnguid = x;
                this.NodeCnt = this.NodeCnt + 1;

            }

            public string getShareName()
            {
                return this.Name;
            }

            public Guid getNodeId()
            {
                return this.NodeId;
            }

            public Guid getShareGuid()
            {
                return this.shareconnguid;
            }

            public void SetShareGuid(Guid x)
            {
                this.shareconnguid = x;
            }

            public Guid searchShareName(string cuser)
            {
                if (this.Name == cuser)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundShareName(string cuser)
            {

                if (this.Name == cuser)
                    return true;
                else
                    return false;
            }
        }


        public class Relationship
        {
            public UInt32 RelationshipId;

            public string StartRelationShipName;
            public string EndRelationShipName;
            public Guid StartNodeId { get; set; }
            public Guid EndNodeId { get; set; }

            public string RelationshipType { get; set; }

            public UInt32 AccessCount;


            public Relationship(Guid m, Guid n, string type, string startname, string endname)
            {
                this.RelationshipId++;
                this.StartNodeId = m;
                this.StartRelationShipName = startname;
                this.EndRelationShipName = endname;
                this.EndNodeId = n;
                this.RelationshipType = type;
                this.AccessCount++;
            }

            public void setAccessCount()
            {
                this.AccessCount = this.AccessCount + 1;
            }
            public Guid getStartNodeId()
            {
                return this.StartNodeId;
            }

            public bool foundsid(Guid gid)
            {
                if (this.StartNodeId == gid)
                    return true;
                else
                    return false;
            }

            public bool founddid(Guid gid)
            {
                if (this.EndNodeId == gid)
                    return true;
                else
                    return false;
            }

            public string getStartRelationshipName()
            {
                return this.StartRelationShipName;
                ;
            }

            public string getEndRelationShipName()
            {
                return this.EndRelationShipName;
            }
            public Guid getEndNodeId()
            {
                return this.EndNodeId;
            }

            public string getRelationship()
            {
                return this.RelationshipType;
            }


        }

        public class User
        {

            public string cUser { get; set; }
            public Guid UserNodeId { get; set; }

            public UInt64 NodeCnt = 0;

            public User()
            {
                //this.UserNodeId = GlobalNodeId;
                this.UserNodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.NodeCnt = this.NodeCnt + 1;
            }


            public User(string cuser)
            {
                this.cUser = cuser;

                this.UserNodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
            }

            public string getUser()
            {
                return this.cUser;
            }

            public Guid getUserNodeId()
            {
                return this.UserNodeId;
            }

            public Guid searchuser(string cuser)
            {
                if (this.cUser == cuser)
                    return this.UserNodeId;
                else
                    return Guid.Empty;
            }

            public bool founduser(string cuser)
            {

                if (this.cUser == cuser)
                    return true;
                else
                    return false;
            }

        }

        public class Process4j
        {
            public Dictionary<string, Guid> process_dict;
            public Dictionary<string, UInt32> process_pid_map;
            public Dictionary<UInt32, UInt32> process_parent_map;
            public Dictionary<UInt32, string> inverse_process_pid_map;
            public Dictionary<string, string> relation_dict;
            public Dictionary<string, UInt32> relation_count;
            public Dictionary<string, string> tdllfunc_dict;
            public Dictionary<string, Guid> tdllfunc_dll_dict; // DLL to GUID Mapping
        }

        public class Neo4jData
        {
            public List<Method> Methods { get; set; }

            public List<User> Users { get; set; }
            public List<Relationship> Relationships { get; set; }

            public List<Computer> Computers { get; set; }

            public List<CIpAddress> CIps { get; set; }

            public List<ShareNames> CShareNames { get; set; }

            public List<NamedPipeSniffer.TrackNamedPipe> CNamedPipes { get; set; }

            public List<CProcessId> xImageName { get; set; }

            public List<WMIOperation> WMIOps { get; set; }

            public List<CImage> xImgLoad { get; set; }

            public List<CPSuspend> xPsuspend { get; set; }

            public List<ConnectionInfo> conninfo { get; set; }

            public List<TDllReaderFunc> tdllfunc { get; set; }

        }

        public class Method
        {
            //private data members

            //private string cuser;
            public Guid NodeId;
            public string cmethod;
            public UInt32 methodcnt;
            public string etw;
            public string dt;
            public UInt64 NodeCnt = 0;
            //method to print student details
            public void printInfo()
            {
                //Console.WriteLine("\tUser     : " + cuser);
                Console.WriteLine("\tMethod   : " + cmethod);
                Console.WriteLine("\tETW      : " + etw);
                //  Console.WriteLine("\tdate     : " + dt.ToString());
                //Console.WriteLine("\ttotalusers:    : " + Program.totalusers);
                Console.WriteLine("\tmethodcnt:    : " + methodcnt);

            }

            public Guid getMethodid()
            {
                return this.NodeId;
            }

            public string getMethod()
            {
                return this.cmethod;
            }

            public string getetw()
            {
                return this.etw;
            }

            public string getdt()
            {
                return this.dt;
            }

            public UInt32 getmethodcnt()
            {
                return this.methodcnt;
            }



            public Method(string mxethod)
            {
                this.etw = "pETW";
                this.dt = DateTime.Now.ToString(@"MM\/dd\/yyyy h\:mm tt");
                this.NodeId = GlobalNodeId;
                GlobalNodeId = Guid.NewGuid();
                this.cmethod = mxethod;
                this.methodcnt++;
                this.NodeCnt = this.NodeCnt + 1;

            }

            public void increment(string name)
            {
                this.methodcnt++;
            }

            public Guid searchmethod(string cmethod)
            {
                if (this.cmethod == cmethod)
                    return this.NodeId;
                else
                    return Guid.Empty;
            }

            public bool foundmethod(string cmethod)
            {
                if (this.cmethod == cmethod)
                    return true;
                else
                    return false;
            }

            /*(public override string ToString()
            {
                return
                  String.Format(" etw: {0,-10} dt: {0,-10} method:{0,-10}",
                                etw,dt, method);
            }*/
        }


        public static Neo4jData mydata;


        public static Process4j myprocess4j;

        static void AddUserList()
        {
            Guid founduserid=Guid.Empty;
            String name=String.Empty;

            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                //Console.WriteLine("Username : {0}", envVar["Name"]);
                name = envVar["Name"].ToString();

                User tuser1 = new User(name);
                founduserid = tuser1.UserNodeId;
                mydata.Users.Add(tuser1);
                Relationship trelation2 = new Relationship(startingGlobalNodeId, founduserid, "has", "Computer", "User");
                mydata.Relationships.Add(trelation2);
            }

            //Console.ReadLine();
            //Add SYSTEM account
            User tuser = new User("SYSTEM");
            founduserid = tuser.UserNodeId;
            mydata.Users.Add(tuser);
            Relationship trelation1 = new Relationship(startingGlobalNodeId, founduserid, "has", "Computer", "User");
            mydata.Relationships.Add(trelation1);

            Console.WriteLine("finished enumerating users");
        }
       

        static void IterateAndAddProcessList()
        {
            UInt32 processid, pprocessid;
            Guid usernameid = Guid.Empty;
            string pname = String.Empty;
            string username = String.Empty;
            bool foundiname = false;
            bool foundpiname = false;
            Guid foundinameid = Guid.Empty;
            Guid foundpinameid = Guid.Empty;
            Boolean valueExists = false;



            Process[] processCollection = Process.GetProcesses();
            foreach (Process p in processCollection)
            {
                foundiname = false;

                try
                {
                   // Console.WriteLine(p.MainModule.FileName);
                    pname = p.MainModule.FileName;
                    pname = pname.ToLower();
                    processid = (uint)p.Id;
                }
                catch
                {

                    pname = String.Empty;
                    processid = 0;
                    continue;

                }
            

                try
                {
                    //var p1 = Process.GetProcessById((int)processid).Parent().Id;
                    //pprocessid = ((uint)p1);
                    Process p1 = ParentProcessUtilities.GetParentProcess((int)processid);
                    pprocessid = (uint)p1.Id;
                    username = ProcessExtensions.GetProcessUser(p);
                }
                catch
                {
                    pprocessid = 0;
                    username = "Error";

                }


                /*
                foreach (CProcessId prid in mydata.xImageName)
                {
                    //Console.WriteLine(prid.imagexname + " for loop" + prid);

                    if (prid.foundCIprocessName(pname))
                    {
                        foundiname = true;
                        //Console.WriteLine("found iname");
                        //foundinameid = prid.NodeId;
                        //prid.NodeCnt++;
                        break;
                        //  foundinameid = prid.searchCIprocessName(data); 
                    }
                }*/
                valueExists = myprocess4j.process_dict.ContainsKey(pname);

                if(valueExists)
                {
                    foundiname = true;
                    continue;
                }
                else
                {
                    CProcessId cimage = new CProcessId(processid, pprocessid, 0, pname, username);
                    mydata.xImageName.Add(cimage);
                    try
                    {
                        myprocess4j.process_dict.Add(pname, cimage.NodeId);
                        myprocess4j.process_pid_map.Add(pname, processid);
                        myprocess4j.process_parent_map.Add(processid, pprocessid);
                        myprocess4j.inverse_process_pid_map.Add(processid, pname);
                        //process_dict.Add
                    }
                    catch
                    {

                    }
                    foreach (User cuser in mydata.Users)
                    {
                        if (cuser.cUser == username)
                        {
                            usernameid = cuser.UserNodeId;
                            break;
                        }
                    }
                    Relationship trelation1 = new Relationship(usernameid, cimage.NodeId, "Created", "User", "ImageName");
                    mydata.Relationships.Add(trelation1);

                }
                /*
                if (foundiname == false)
                {
                    //Console.WriteLine(pname);

                    CProcessId cimage = new CProcessId(processid, pprocessid, 0, pname, username);
                    mydata.xImageName.Add(cimage);
                    try
                    {
                        myprocess4j.process_dict.Add(pname, cimage.NodeId);
                        myprocess4j.process_pid_map.Add(pname, processid);
                        //process_dict.Add
                    }
                    catch
                    {

                    }
                    foreach (User cuser in mydata.Users)
                    {
                        if (cuser.cUser == username)
                        {
                            usernameid = cuser.UserNodeId;
                            break;
                        }
                    }
                    Relationship trelation1 = new Relationship(usernameid, cimage.NodeId, "Created", "User", "ImageName");
                    mydata.Relationships.Add(trelation1);

                }
                */
            }

            /*
             foreach (Process p in processCollection)
             {
                 try
                 {
                     processid = (uint)p.Id;
                     var p1 = Process.GetProcessById((int)processid).Parent().Id;
                     pprocessid = ((uint)p1);
                 }
                 catch
                 {
                     continue;
                 }
                 foreach (CProcessId cp in mydata.xImageName)
                 {
                     if (cp.processId == pprocessid)
                     {
                         Guid x2 = process_dict[p.MainModule.FileName];
                         Relationship trelation1 = new Relationship(cp.NodeId, x2, "ParentOf", "ImageName", "ImageName");
                         mydata.Relationships.Add(trelation1);
                         break;
                     }
                 }
              }
              */
            Console.WriteLine("Finished Enumerating Process");

        }

        public static bool isLocal(string host)
        {
            try
            {
                IPAddress[] hostIPs = Dns.GetHostAddresses(host);
                // get local IP addresses
                IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());

                // test if any host IP equals to any local IP or to localhost
                foreach (IPAddress hostIP in hostIPs)
                {
                    // is localhost
                    if (IPAddress.IsLoopback(hostIP)) return true;
                    // is local address
                    foreach (IPAddress localIP in localIPs)
                    {
                        if (hostIP.Equals(localIP)) return true;
                    }
                }
            }
            catch { }
            return false;
        }

        static void Main(string[] args)
        {
            Console.WriteLine();
            Console.WriteLine("ETW Hound v" + Assembly.GetExecutingAssembly().GetName().Version.ToString());
            Console.WriteLine();

            mydata = new Neo4jData
            {
                Computers = new List<Computer>(),
                Relationships = new List<Relationship>(),
                Methods = new List<Method>(),
                Users = new List<User>(),
                CIps = new List<CIpAddress>(),
                CShareNames = new List<ShareNames>(),
                CNamedPipes = new List<NamedPipeSniffer.TrackNamedPipe>(),
                xImageName = new List<CProcessId>(),
                WMIOps = new List<WMIOperation>(),
                xImgLoad = new List<CImage>(),
                xPsuspend = new List<CPSuspend>(),
                conninfo = new List<ConnectionInfo>(),
                tdllfunc = new List<TDllReaderFunc>()
            };

            myprocess4j = new Process4j
            {
                process_dict = new Dictionary<string, Guid>(),
                process_pid_map = new Dictionary<string,UInt32>(),
                process_parent_map = new Dictionary<UInt32,UInt32>(),
                inverse_process_pid_map = new Dictionary<UInt32,string>(),
                relation_dict  = new Dictionary<string,string>(),
                relation_count = new Dictionary<string,UInt32>(),
                tdllfunc_dict  =  new Dictionary<string,string>(),
                tdllfunc_dll_dict = new Dictionary<string,Guid>()
            };

            var trace = new UserTrace("ETWHound");


            EventLogSession session = new EventLogSession();

            EventLogQuery query = new EventLogQuery("Security", PathType.LogName, "*[System/EventID=5156]")
            {
                TolerateQueryErrors = true,
                Session = session
            };

            EventLogWatcher logWatcher = new EventLogWatcher(query);

            logWatcher.EventRecordWritten += new EventHandler<EventRecordWrittenEventArgs>(LogWatcher_EventRecordWritten);

           

            Computer mycomp = new Computer(System.Environment.MachineName);
            mydata.Computers.Add(mycomp);
            startingGlobalNodeId = mycomp.NodeId;


            foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
               
                IPInterfaceProperties ipProps = netInterface.GetIPProperties();

                foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
                {
                   // Console.WriteLine(" " + addr.Address.ToString());
                    CIpAddress cip = new CIpAddress(addr.Address.ToString(),"0");
                    mydata.CIps.Add(cip);
                    Relationship trelation1 = new Relationship(startingGlobalNodeId, cip.NodeId, "has", "Computer", "IPAddress");
                    mydata.Relationships.Add(trelation1);

                }

             
            }

            //
            // Parse the arguments
            //
            bool onlyNewPipes = false;
            bool forceFetchInterfacesInfo = false;
            bool forceExtractMethodNames = false;
            bool onlyMojo = false;
            foreach (string argument in args)
            {
                if (argument.Contains("--update-interfaces-info")) { forceFetchInterfacesInfo = true; forceExtractMethodNames = true; }
                else if (argument.Contains("--only-new-mojo-pipes")) onlyNewPipes = true;
                else if (argument.Contains("--extract-method-names")) forceExtractMethodNames = true;
                else if (argument.Contains("--only-mojo")) onlyMojo = true;
                else if (argument.Contains("-h") || argument.Contains("--help") || argument.Contains("/?")) { ShowUsage(); return; }
                else
                {
                    Console.WriteLine("[!] Unrecognized argument '{0}'", argument);
                    return;
                }
            }

           // Console.WriteLine("Type -h to get usage help and extended options");
            Console.WriteLine();

            Console.WriteLine("[+] Starting up");

            HandlesUtility.EnumerateExistingHandles(NamedPipeSniffer.GetRunningChromeProcesses());

            DateTime currentDateTime1 = DateTime.Now;
            Console.WriteLine("Current date and time: " + currentDateTime1);

            AddUserList();
            IterateAndAddProcessList();

          

            DateTime currentDateTime = DateTime.Now;
            Console.WriteLine("Current date and time: " + currentDateTime);

         
            //
            // Start sniffing
            //

            string outputPipeName = "chromeipc";
            string outputPipePath = @"\\.\pipe\" + outputPipeName;
            Console.WriteLine("[+] Starting sniffing of chrome named pipe to " + outputPipePath + ".");

            NamedPipeSniffer pipeMonitor = new NamedPipeSniffer(outputPipeName, onlyMojo ? "mojo" : "", onlyNewPipes);



            var powershellProvider = new Provider("Microsoft-Windows-PowerShell");
            var SMBShellProvider = new Provider("Microsoft-Windows-SMBServer");

            var ProcessProvider = new Provider("Microsoft-Windows-Kernel-Process");

           // var securitytrace = new UserTrace("EventLog-Security");
           // var provider = new Provider("Microsoft-Windows-Security-Auditing"
          //  var SecurityProvider = new Provider("Microsoft-Windows-Security-Auditing");

            var WMIProvider = new Provider("Microsoft-Windows-WMI-Activity");

            var NetworkProvider = new Provider("Microsoft-Windows-Kernel-Network");

            //var ThreatIntelProvider = new Provider("Microsoft-Windows-Threat-Intelligence");


            var powershellFilter = new EventFilter(
              Filter.EventIdIs(7937)
              .And(UnicodeString.Contains("Payload", "Started")));

            var SMBshellFilter = new EventFilter(Filter.EventIdIs(600).Or(Filter.EventIdIs(500)));

            var ProcessFilter = new EventFilter(Filter.EventIdIs(1).Or(Filter.EventIdIs(3)).Or(Filter.EventIdIs(5)));

           // var SecurityFilter = new EventFilter(Filter.EventIdIs(5156));

            var WMIFilter = new EventFilter(Filter.EventIdIs(11));

            var NetworkFilter = new EventFilter(Filter.EventIdIs(15).Or(Filter.EventIdIs(12)));

            //var ThreatFilter = new EventFilter(Filter.EventIdIs(3));

            powershellFilter.OnEvent += OnEvent;

            SMBshellFilter.OnEvent += OnSMBEvent;

            ProcessFilter.OnEvent += OnProcessEvent;

          //  SecurityFilter.OnEvent += OnSecurityEvent;

            WMIFilter.OnEvent += OnWMIEvent;

            NetworkFilter.OnEvent += OnNetworkEvent;

            powershellProvider.Any = 0x20;
            powershellProvider.AddFilter(powershellFilter);

            SMBShellProvider.Any = 0x00;
            SMBShellProvider.AddFilter(SMBshellFilter);


            ProcessProvider.Any = 0x00;
            ProcessProvider.AddFilter(ProcessFilter);


           // SecurityProvider.Any = 0x00;
          //  SecurityProvider.AddFilter(SecurityFilter);

            WMIProvider.Any = 0x00;
            WMIProvider.AddFilter(WMIFilter);


            NetworkProvider.Any = 0x00;
            NetworkProvider.AddFilter(NetworkFilter);


            trace.Enable(powershellProvider);

            trace.Enable(SMBShellProvider);
            //     Console.WriteLine("before starting trace");
            trace.Enable(ProcessProvider);
            //     Console.WriteLine("starting process provider");
            //trace.Enable(SecurityProvider);

            trace.Enable(WMIProvider);

           // trace.Enable(NetworkProvider);

            //securitytrace.Enable(SecurityProvider);

            try
            {
                logWatcher.Enabled = true;
            }
            catch (EventLogException ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }



            bool isMonitoring = pipeMonitor.Start();




            //
            // Set up clean up routines
            //
            Console.CancelKeyPress += delegate
            {
                Thread.CurrentThread.IsBackground = false;
                Console.WriteLine("Control C event entered");
                pipeMonitor.Stop();

                try
                {
                    logWatcher.Enabled = false;
                }
                catch (EventLogException ex)
                {
                    Console.WriteLine(ex.Message);
                    Console.ReadLine();
                }


                if (trace != null)
                {

                    Console.WriteLine("Control C event");
               


                 
                    trace.Stop();
                   // securitytrace.Stop();


                    Console.WriteLine("Trace stopped");
                    System.Threading.Thread.Sleep(2000);


                }


                var jsonData = JsonConvert.SerializeObject(mydata, Newtonsoft.Json.Formatting.Indented);
              //  Console.WriteLine(jsonData);
                File.WriteAllText("C:\\NTT\\ETWHound.json", jsonData);
                GenerateComputerNodesCypher();
                GenerateUserNodesCypher();
                GenerateMethodNodesCypher();
                GenerateIPAddressCypher();
                GenerateShareNamesCypher();
                GenerateNamedPipesCypher();
                GenerateImageCypher();
                GenerateWMIOpscypher();
                GenerateRelationShips();
                GenerateImageLoadCypher();
                GenerateDllImageFuncCypher();
              

            };


            trace.Start();
            //securitytrace.Start();
            Console.WriteLine("starting trace");

        }

        static void ShowUsage()
        {
            Console.WriteLine(
            @"Syntax: chromeipc [options]
Available options:

    Capturing:
        --only-mojo
            Records only packets sent over a ""\\mojo.*"" pipe (without ""\\chrome.sync.*"", etc.).

        --only-new-mojo-pipes
            Records only packets sent over mojo AND newly-created pipes since the start of the capture
            This helps reducing noise and it might improve performance
            (example: opening a new tab will create a new mojo pipe).
            
    Interface resolving:
        --update-interfaces-info
            Forcefully re-scan the chromium sources (from the internet) and populate the *_interfaces.json files.
            This might take a few good minutes. Use this if you see wrong interfaces info and wish to update

        --extract-method-names
            Forcefully re-scan chrome.dll file to find the message IDs and update the mojo_interfaces_map.lua file
            This should happen automaticlly whenever chrome.dll changes.
                            ");

        }



        static string RemoveSpecialChars(string input)
        {
            return Regex.Replace(input, @"[^0-9a-zA-Z]", string.Empty);
        }

        static void GenerateWMIOpscypher()
        {
            string filename = @"WMIOps.cql";
            var output = new StringBuilder();


            foreach (WMIOperation cid in mydata.WMIOps)
            {
                string nodename = RemoveSpecialChars(cid.Name);
                string s = $"CREATE (W{nodename}:WMIOperation {{ NodeId: '{RemoveSpecialChars(cid.NodeId.ToString())}' , WMIOperation: '{cid.Name}' , NodeCnt:'{cid.NodeCnt}' }} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());
        }

        static void GenerateImageLoadCypher()
        {
            string filename = @"ProcessLoad.cql";
            var output = new StringBuilder();


            foreach (CImage cid in mydata.xImgLoad)
            {
                string nodename = RemoveSpecialChars(cid.imagexload);
                string s = $"CREATE (:ImageLoadName {{ NodeId: '{RemoveSpecialChars(cid.NodeId.ToString())}' , ImageName: '{cid.imagexload}', ProcessId: '{cid.processId}' , Imagechecksum: '{cid.ImageChecksum}' , NodeCnt:'{cid.NodeCnt}' , Imagesize:'{cid.imagesize}',  Imagebase:'{cid.imagebase}',  TimeStamp:'{cid.imagesize}' }} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());

        }
        static void GenerateImageCypher()
        {
            string filename = @"Process.cql";
            var output = new StringBuilder();


            foreach (CProcessId cid in mydata.xImageName)
            {
                string nodename = RemoveSpecialChars(cid.imagexname);
                string s = $"CREATE (:ImageName {{ NodeId: '{RemoveSpecialChars(cid.NodeId.ToString())}' , ImageName: '{cid.imagexname}', ProcessId: '{cid.processId}' , PProcessId: '{cid.parentProcessId}' , NodeCnt:'{cid.NodeCnt}' }} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());

        }
        static void GenerateNamedPipesCypher()
        {
            string filename = @"Namedpipes.cql";
            var output = new StringBuilder();


            foreach (NamedPipeSniffer.TrackNamedPipe tnp in mydata.CNamedPipes)
            {
                string nodename = RemoveSpecialChars(tnp.Name);
                string s = $"CREATE (:NamedPipe {{ NodeId: '{RemoveSpecialChars(tnp.NodeId.ToString())}' , PipeName: '{tnp.Name}' }} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());

        }

        static void GenerateDllImageFuncCypher()
        {

            string filename = @"dllfunc.cql";
            var output = new StringBuilder();


            foreach (TDllReaderFunc iip in mydata.tdllfunc)
            {
                string nodename = RemoveSpecialChars(iip.Name);
                
                string s = $"CREATE (:DllFunc {{ NodeId: '{RemoveSpecialChars(iip.NodeId.ToString())}' , DllFunc: '{nodename}' , DllName: '{iip.DLLname}' , NodeCnt:'{iip.NodeCnt}'}} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());
        }
        static void GenerateIPAddressCypher()
        {
            string filename = @"ipaddress.cql";
            var output = new StringBuilder();


            foreach (CIpAddress iip in mydata.CIps)
            {
                string nodename = RemoveSpecialChars(iip.getCIpAddress());
                string s = $"CREATE (I{nodename}:IPAddress {{ NodeId: '{RemoveSpecialChars(iip.getNodeId().ToString())}' , IPAddress: '{iip.getCIpAddress()}' , NodeCnt:'{iip.NodeCnt}'}} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());

        }
        static void GenerateShareNamesCypher()
        {
            string filename = @"sharenames.cql";
            var output = new StringBuilder();


            foreach (ShareNames ishares in mydata.CShareNames)
            {
                string nodename = RemoveSpecialChars(ishares.getShareName());
                string s = $"CREATE (S{nodename}:ShareName {{ NodeId: '{RemoveSpecialChars(ishares.getNodeId().ToString())}' , ShareName: '{ishares.getShareName()}', NodeCnt:'{ishares.NodeCnt}' }} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());
        }
        static void GenerateComputerNodesCypher()
        {
            string filename = @"computers.cql";
            var output = new StringBuilder();


            foreach (Computer icomputer in mydata.Computers)
            {
                string nodename = RemoveSpecialChars(icomputer.getComputer());
                string s = $"CREATE (C{nodename}:Computer {{ NodeId: '{RemoveSpecialChars(icomputer.getNodeId().ToString())}' , computername: '{icomputer.getComputer()}' , NodeCnt:'{icomputer.NodeCnt}'}} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());
        }

        static void GenerateMethodNodesCypher()
        {
            string filename = @"methods.cql";
            var output = new StringBuilder();


            foreach (Method imethod in mydata.Methods)
            {
                string nodename = RemoveSpecialChars(imethod.getMethod());
                string s = $"CREATE (M{nodename}:Method {{ NodeId: '{RemoveSpecialChars(imethod.getMethodid().ToString())}' , methodname: '{imethod.getMethod()}' , NodeCnt:'{imethod.NodeCnt}'}} ) ";
                output.AppendLine(s);
            }


            File.WriteAllText(filename, output.ToString());
        }

        static UInt64 globalrelationshipId = 0;
        static void GenerateRelationShips()
        {
            string filename = @"relationships.cql";
            var output = new StringBuilder();
            string construct = string.Empty;



            foreach (Relationship irelationship in mydata.Relationships)
            {
                UInt64 rel_id = globalrelationshipId;
                UInt32 access_count = 0;

               if(irelationship.getRelationship() == "has")
                {
                    rel_id = 0;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship() == "Created")
                {
                    rel_id = 1;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship() == "ReadWrite")
                {
                    rel_id = 2;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship() == "NamedOps")
                {
                    rel_id = 3;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship()== "ImageLoad")
                {
                    rel_id = 4;
                    construct = irelationship.getStartNodeId().ToString() + ";" + irelationship.getEndNodeId().ToString();
                    access_count = myprocess4j.relation_count[construct];
                }
                if (irelationship.getRelationship()== "Inbound")
                {
                    rel_id = 5;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship()== "invokes")
                {
                    rel_id = 6;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship() == "Accessed")
                {
                    rel_id = 7;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship() == "Outbound")
                {
                    rel_id = 8;
                    access_count = irelationship.AccessCount;
                }
                if (irelationship.getRelationship() == "Export")
                {
                    rel_id = 9;
                    construct = irelationship.getStartNodeId().ToString() + ";" + irelationship.getEndNodeId().ToString();
                    access_count = myprocess4j.relation_count[construct];
                }
               
                string nodename = RemoveSpecialChars(irelationship.getStartRelationshipName());
                //string s = $"MATCH (a:{nodename}), (b:{irelationship.getEndRelationShipName()}) WHERE a.NodeId = '{RemoveSpecialChars(irelationship.getStartNodeId().ToString())}' AND b.NodeId = '{RemoveSpecialChars(irelationship.getEndNodeId().ToString())}' CREATE(a) -[r{rel_id}:{irelationship.getRelationship()}]->(b) RETURN type(r{rel_id}); ";
                string s = $"MATCH (a:{nodename}), (b:{irelationship.getEndRelationShipName()}) WHERE a.NodeId = '{RemoveSpecialChars(irelationship.getStartNodeId().ToString())}' AND b.NodeId = '{RemoveSpecialChars(irelationship.getEndNodeId().ToString())}' CREATE(a) -[r{rel_id}:{irelationship.getRelationship()} {{ AccessCount: {access_count} }}]->(b) RETURN type(r{rel_id}); ";
                output.AppendLine(s);
                s = "WITH 1 as dummy";
                output.AppendLine(s);
                globalrelationshipId++;
            }

            File.WriteAllText(filename, output.ToString());

        }
        static void GenerateUserNodesCypher()
        {
            string filename = @"users.cql";
            var output = new StringBuilder();



            foreach (User iuser in mydata.Users)
            {
                string nodename = RemoveSpecialChars(iuser.getUser());
                string s = $"CREATE (U{nodename}:User{{ NodeId: '{RemoveSpecialChars(iuser.getUserNodeId().ToString())}' , username: '{iuser.getUser()}' ,   NodeCnt:'{iuser.NodeCnt}' }} ) ";
                output.AppendLine(s);
            }

            File.WriteAllText(filename, output.ToString());
        }


        // These represent strings in the 7937 ContextInfo payload.
        // They're always in this format, with each key/value pair separated
        // by a \n\r. For more information, use Message Analyzer to look
        // at the 7937 event structure.
        private const string HostAppKey = "Host Application = ";
        private const string CmdNameKey = "Command Name = ";
        private const string CmdTypeKey = "Command Type = ";
        private const string UserNameKey = "User = ";

        static void OnWMIEvent(IEventRecord record)
        {
            string data = string.Empty;
            string userx = string.Empty;
            string Direction = string.Empty;
            string namespacename = String.Empty;
            UInt32 processid;
            bool foundiname = false;
            Guid foundinameid = Guid.Empty;
            bool foundcomp = false;
            Guid foundicomp = Guid.Empty;
            bool foundu = false;
            Guid foundiu = Guid.Empty;

            Monitor.Enter(_object);

            //Console.WriteLine("WMI Operation entered");
            try
            {

                if (record.TryGetUnicodeString("Operation", out data))
                {
                    
                }

                if (record.TryGetUnicodeString("NamespaceName", out namespacename))
                {
                   

                }
                

                if (record.TryGetUnicodeString("ClientMachine", out data))
                {
                    //Console.WriteLine(data);
                   


                   


                }
                if (record.TryGetUnicodeString("User", out userx))
                {
                    //Console.WriteLine(data);
                    //Console.WriteLine(data);
                  

                }

                //Console.WriteLine(data);
                foreach (WMIOperation wmix in mydata.WMIOps)
                {
                    if (wmix.foundWMIOperation(data))
                    {
                        foundiname = true;
                        foundinameid = wmix.searchWMIOperation(data);
                        wmix.NodeCnt++;
                        break;
                    }
                }

                if (foundiname == false)
                {
                    
                    WMIOperation wmiops = new WMIOperation(data, namespacename);
                    mydata.WMIOps.Add(wmiops);
                    foundinameid = wmiops.NodeId;
                
                }

                foreach (Computer prico in mydata.Computers)
                {
                    if (prico.foundComputer(data))
                    {
                        foundcomp = true;
                        foundicomp = prico.searchComputer(data);
                        prico.NodeCnt++;
                        break;
                    }
                }
                if (foundcomp == false)
                {
                    Computer comp = new Computer(data);
                    mydata.Computers.Add(comp);
                    foundicomp = comp.NodeId;

                    Relationship trelation1 = new Relationship(foundicomp, foundinameid, "Operation", "Computer", "WMIOperation");
                    mydata.Relationships.Add(trelation1);
                }

                foreach (User priu in mydata.Users)
                {
                    if (priu.founduser(userx))
                    {
                        foundu = true;
                        foundiu = priu.searchuser(userx);
                        priu.NodeCnt++;
                        break;
                    }
                    
                }

                if (foundu == false)
                {
                    User iuser = new User(userx);
                    mydata.Users.Add(iuser);
                    foundiu = iuser.UserNodeId;
                    Relationship trelation1 = new Relationship(startingGlobalNodeId, foundiu, "has", "Computer", "User");
                    mydata.Relationships.Add(trelation1);

                   
                }

                if(foundiname == false )
                {
                    Relationship trelation2 = new Relationship(foundiu, foundinameid, "Operation", "User", "WMIOperation");
                    mydata.Relationships.Add(trelation2);
                }


            }
            finally
            {
                Monitor.Exit(_object);
            }
            //Console.WriteLine("WMI Operation exit");
        }


        static void OnThreatEvent(IEventRecord record)
        {
            Console.WriteLine("Threat Event");
        }

        public static IPAddress UInt32ToIPAddress(UInt32 address)
        {
           // return new IPAddress(new byte[] {
             //   (byte)((address>>24) & 0xFF) ,
            //    (byte)((address>>16) & 0xFF) ,
            //    (byte)((address>>8)  & 0xFF) ,
             //   (byte)( address & 0xFF)});

            return new IPAddress(new byte[] {
                (byte)(address & 0xFF) ,
                (byte)((address>>8) & 0xFF) ,
                (byte)((address>>16)  & 0xFF) ,
                (byte)((address>>24) & 0xFF)});
        }

        public static void LogWatcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            //string content = "The Windows Filtering Platform has permitted a connection.\n\nApplication Information:\n        Process ID:             2404\n        Application Name:       \\device\\harddiskvolume2\\program files\\splunk\\bin\\python3.exe\n\nNetwork Information:\n        Direction:              Outbound\n        Source Address:         127.0.0.1\n        Source Port:            51234\n        Destination Address:    127.0.0.1\n        Destination Port:               8089\n        Protocol:               6\n        Interface Index:                1\n\nFilter Information:\n        Filter Origin:          AppContainer Loopback\n        Filter Run-Time ID:     66640\n        Layer Name:             Connect\n        Layer Run-Time ID:      48\n        Remote User ID:         S-1-0-0\n        Remote Machine ID:      S-1-0-0";

            /*
            var time = e.EventRecord.TimeCreated;
            var id = e.EventRecord.Id;
            var logname = e.EventRecord.LogName;
            var level = e.EventRecord.Level;
            var task = e.EventRecord.TaskDisplayName;
            var opCode = e.EventRecord.OpcodeDisplayName;
            var mname = e.EventRecord.MachineName;*/
            String content = e.EventRecord.FormatDescription();
            string data = string.Empty;
            string pdata = string.Empty;
            string Direction = string.Empty;

            UInt32 sip;
            UInt32 dip;
            UInt32 processid = 0;
            UInt32 pprocessid = 0;
            string connid = string.Empty;

            String sourceip = String.Empty;
            String destip = String.Empty;
            char[] stringArray;
            Guid Event5processNodeId = Guid.Empty;
            bool foundiname = false;
            Guid foundinameid = Guid.Empty;
            bool foundsipaddress = false;
            Guid foundsipid = Guid.Empty;
            Guid founddipid = Guid.Empty;
            String username = String.Empty;
            bool founddipaddress = false;
            Guid usernameid = Guid.Empty;

            //Console.WriteLine($@"{time}, {id}, {logname}, {level}, {task}, {opCode}, {mname}");
            //Console.WriteLine(content);

            Regex regex = new Regex(@"(\w+( \w+)*):\s+([^\n\r]+)");
            MatchCollection matches = regex.Matches(content);

            ConnectionInfo cip = new ConnectionInfo();

            foreach (Match match in matches)
            {
                string key = match.Groups[1].Value.Trim();
                string value = match.Groups[3].Value.Trim();

                // Set the corresponding property based on the key
                switch (key)
                {
                    case "Application Information":
                        //Console.WriteLine(value);
                        string pattern1 = @"\d+";

                        Match match1 = Regex.Match(value, pattern1);
                        int rprocessid = Int32.Parse(match1.Value);
                        //Console.WriteLine($"Process ID: {processId}")
                        cip.ProcessId = rprocessid.ToString();
                        break;

                    case "Process ID":
                        cip.ProcessId = value;
                        break;
                    case "Application Name":
                        cip.ApplicationName = value;
                        break;
                    case "Network Information":
                        string delimiter = ":";

                        int delimiterIndex = value.IndexOf(delimiter);
                        if (delimiterIndex != -1)
                        {
                            string extractedString = value.Substring(delimiterIndex + delimiter.Length).TrimStart();
                            cip.Direction = extractedString;
                        }

                        break;
                    case "Direction":
                        cip.Direction = value;
                        break;
                    case "Source Address":
                        cip.SourceAddress = value;
                        break;
                    case "Source Port":
                        cip.SourcePort = value;
                        break;
                    case "Destination Address":
                        cip.DestinationAddress = value;
                        break;
                    case "Destination Port":
                        cip.DestinationPort = value;
                        break;
                    case "Protocol":
                        cip.Protocol = value;
                        break;
                    case "Interface Index":
                        cip.InterfaceIndex = value;
                        break;
                    case "Filter Origin":
                        cip.FilterOrigin = value;
                        break;
                    case "Filter Run-Time ID":
                        cip.FilterRunTimeId = value;
                        break;
                    case "Layer Name":
                        cip.LayerName = value;
                        break;
                    case "Layer Run-Time ID":
                        cip.LayerRunTimeId = value;
                        break;
                    case "Remote User ID":
                        cip.RemoteUserId = value;
                        break;
                    case "Remote Machine ID":
                        cip.RemoteMachineId = value;
                        break;
                }
            }

          // Console.WriteLine("source : " + cip.ProcessId + "direction :" + cip.Direction);

            connid = cip.ProcessId;
            sourceip = cip.SourceAddress;
            destip = cip.DestinationAddress;
            if(cip.ApplicationName  != "System")
            {
                data = DevicePathMapper.FromDevicePath(cip.ApplicationName);
            }
            else
            {
                data = "System";
            }

            //Console.WriteLine(data);
            //Console.WriteLine(cip.ApplicationName);
            string originalString = data;
            string searchString = "\\device\\harddiskvolume";
            string replacementString = "\\Device\\HarddiskVolume";
            String modifiedString = String.Empty;

            if (data != "System")
            {
                try
                {
                    modifiedString = originalString.Replace(searchString, replacementString);
                }
                catch
                {
                    modifiedString = originalString;
                }
                //Console.WriteLine(modifiedString);
                try
                {
                    data = DevicePathMapper.FromDevicePath(modifiedString);
                }
                catch
                {

                }
            }

            processid = uint.Parse(connid);

            //Console.WriteLine(data);

            try
            {
                if (myprocess4j.process_dict.ContainsKey(data))
                {

                    foundiname = true;
                    foundinameid = myprocess4j.process_dict[data];
                }
                else
                {
                    Console.WriteLine("not in dict");

                    try
                    {
                        // pprocessid = (uint)Process.GetProcessById(int.Parse(connid)).Parent().Id;
                            Process p1 = ParentProcessUtilities.GetParentProcess((int)processid);
                            pprocessid = (uint)p1.Id;
                        //pprocessid = 0;
                    }
                    catch
                    {
                        pprocessid = 0;
                    }

                    CProcessId cimage2 = new CProcessId(processid, pprocessid, 0, data, "Empty");
                    foundinameid = cimage2.NodeId;
                    mydata.xImageName.Add(cimage2);
                    try
                    {
                        myprocess4j.process_dict.Add(data, cimage2.NodeId);
                        myprocess4j.process_pid_map.Add(data, processid);
                        myprocess4j.process_parent_map.Add(processid, pprocessid);
                    }
                    catch { }

                    try
                    {
                        Process p = Process.GetProcessById((int)processid);
                        username = ProcessExtensions.GetProcessUser(p);


                        foreach (User cuser in mydata.Users)
                        {
                            if (cuser.cUser == username)
                            {
                                usernameid = cuser.UserNodeId;

                                break;
                            }
                        }
                        Relationship trelation1 = new Relationship(usernameid, foundinameid, "Created", "User", "ImageName");
                        mydata.Relationships.Add(trelation1);
                    }
                    catch
                    {
                    }

                }
                // Process p = Process.GetProcessById(int.Parse(connid));
                //  data = p.ProcessName;
                //data = Path.GetPathRoot(cip.ApplicationName) + cip.ApplicationName.Substring(19);

                try
                {
                    //Console.WriteLine(data);
                    Event5processNodeId = myprocess4j.process_dict[data];
                }
                catch
                {
                    Event5processNodeId = Guid.Empty;
                }

                //Console.WriteLine("event5 : " +  Event5processNodeId);

                foreach (CIpAddress iip in mydata.CIps)
                {

                    if (iip.foundCIpAddress(sourceip))
                    {
                        foundsipaddress = true;
                        foundsipid = iip.searchCIpAddress(sourceip);
                        iip.NodeCnt++;
                        break;
                    }
                }

                foreach (CIpAddress iip in mydata.CIps)
                {

                    if (iip.foundCIpAddress(destip))
                    {
                        founddipaddress = true;
                        founddipid = iip.NodeId;
                        iip.NodeCnt++;
                        break;

                    }
                }
                if (foundsipaddress == false)
                {
                    CIpAddress cip1 = new CIpAddress(sourceip, connid);
                    mydata.CIps.Add(cip1);
                    foundsipid = cip1.NodeId;
                }

                if (founddipaddress == false && sourceip != destip)
                {
                    CIpAddress cip2 = new CIpAddress(destip, connid);
                    mydata.CIps.Add(cip2);
                    founddipid = cip2.NodeId;
                }

                if (foundsipaddress == true && founddipaddress == true)
                {
                    if (cip.Direction == "Inbound")
                    {
                        Relationship trelation3 = new Relationship(founddipid, Event5processNodeId, "Inbound", "IPAddress", "ImageName");
                        mydata.Relationships.Add(trelation3);


                        Relationship trelation4 = new Relationship(founddipid, foundsipid, "Inbound", "IPAddress", "IPAddress");
                        mydata.Relationships.Add(trelation4);

                    }
                    else
                    {
                        Relationship trelation3 = new Relationship(foundsipid, founddipid, "Outbound", "IPAddress", "IPAddress");
                        mydata.Relationships.Add(trelation3);

                        Relationship trelation4 = new Relationship(Event5processNodeId, founddipid, "Outbound", "ImageName", "IPAddress");
                        mydata.Relationships.Add(trelation4);
                    }


                }
                else
                {

                    if (cip.Direction == "Inbound")
                    {
                        Relationship trelation3 = new Relationship(founddipid, Event5processNodeId, "Inbound", "IPAddress", "ImageName");
                        mydata.Relationships.Add(trelation3);


                        Relationship trelation4 = new Relationship(founddipid, foundsipid, "Inbound", "IPAddress", "IPAddress");
                        mydata.Relationships.Add(trelation4);


                    }
                    else
                    {
                        Relationship trelation3 = new Relationship(foundsipid, founddipid, "Outbound", "IPAddress", "IPAddress");
                        mydata.Relationships.Add(trelation3);

                        Relationship trelation4 = new Relationship(Event5processNodeId, founddipid, "Outbound", "ImageName", "IPAddress");
                        mydata.Relationships.Add(trelation4);
                    }

                }
            }
            catch
            {
                Console.WriteLine("Empty data set received :" + data);
                Console.WriteLine(content);

            }
        }

        static void OnNetworkEvent(IEventRecord record)
        {
            string data = string.Empty;
            string pdata = string.Empty;
            string Direction = string.Empty;

            UInt32 sip;
            UInt32 dip;
            UInt32 processid = 0;
            UInt32 pprocessid = 0;
            string connid = string.Empty;

            String sourceip = String.Empty;
            String destip = String.Empty;
            char[] stringArray;
            Guid Event5processNodeId= Guid.Empty;
            bool foundiname = false;
            Guid foundinameid = Guid.Empty;
            bool foundsipaddress = false;
            Guid foundsipid = Guid.Empty;
            Guid founddipid = Guid.Empty;

            bool founddipaddress = false;

            if (record.TryGetUInt32("connid", out processid)) //Event ID 500
            {
                connid = processid.ToString();
                try
                {
                    Event5processNodeId = myprocess4j.process_dict[myprocess4j.inverse_process_pid_map[processid]];
                }
                catch
                {
                    Event5processNodeId = Guid.Empty;
                }


            }
            if (record.TryGetUInt32("daddr", out dip)) //Event ID 500
            {
                destip = UInt32ToIPAddress(dip).ToString();
                //Console.WriteLine("destip: " + destip);
            }
            if (record.TryGetUInt32("saddr", out sip)) //Event ID 500
            {

                sourceip = UInt32ToIPAddress(sip).ToString();
                //Console.WriteLine("sourceip:" + sourceip);
            }

           

            foreach (CIpAddress iip in mydata.CIps)
            {
         
                if (iip.foundCIpAddress(sourceip))
                {
                    foundsipaddress = true;
                    foundsipid = iip.searchCIpAddress(sourceip);
                    iip.NodeCnt++;
                    break;
                }
            }

            foreach (CIpAddress iip in mydata.CIps)
            {
           
                if (iip.foundCIpAddress(destip))
                {
                    founddipaddress = true;
                    founddipid = iip.NodeId;
                    iip.NodeCnt++;
                    break;

                }
            }
            if (foundsipaddress == false)
            {
                CIpAddress cip = new CIpAddress(sourceip, connid);
                mydata.CIps.Add(cip);
                foundsipid = cip.NodeId;
            }

            if (founddipaddress == false && sourceip != destip )
            {
                CIpAddress cip = new CIpAddress(destip, connid);
                mydata.CIps.Add(cip);
                founddipid = cip.NodeId;
            }

            if (foundsipaddress == true && founddipaddress == true)
            {
                if (isLocal(destip))
                {

                    Relationship trelation3 = new Relationship(founddipid, Event5processNodeId, "Inbound", "IPAddress", "ImageName");
                    mydata.Relationships.Add(trelation3);


                    Relationship trelation4 = new Relationship(founddipid, foundsipid, "Inbound", "IPAddress", "IPAddress");
                    mydata.Relationships.Add(trelation4);

                    
                }
                else
                {
                    Relationship trelation3 = new Relationship(foundsipid, founddipid, "Outbound", "IPAddress", "IPAddress");
                    mydata.Relationships.Add(trelation3);

                    Relationship trelation4 = new Relationship(Event5processNodeId, founddipid, "Outbound", "ImageName", "IPAddress");
                    mydata.Relationships.Add(trelation4);
                }


            }
            else
            {

                if (isLocal(destip))
                {
                    Relationship trelation3 = new Relationship(founddipid, Event5processNodeId, "Inbound", "IPAddress", "ImageName");
                    mydata.Relationships.Add(trelation3);


                    Relationship trelation4 = new Relationship(founddipid, foundsipid, "Inbound", "IPAddress", "IPAddress");
                    mydata.Relationships.Add(trelation4);


                }
                else
                {
                    Relationship trelation3 = new Relationship(foundsipid, founddipid, "Outbound", "IPAddress", "IPAddress");
                    mydata.Relationships.Add(trelation3);

                    Relationship trelation4 = new Relationship(Event5processNodeId, founddipid, "Outbound", "ImageName", "IPAddress");
                    mydata.Relationships.Add(trelation4);
                }

            }

        }

        static void OnSecurityEvent(IEventRecord record)
        {

            string data = string.Empty;
            string pdata = string.Empty;
            string Direction = string.Empty;

            string sip = string.Empty;
            string dip = string.Empty;
            UInt32 processid;
            UInt32 pprocessid = 0;

            Console.WriteLine("security event");

            if (record.TryGetUnicodeString("Application", out data))
            {
                //Console.WriteLine(data);


            }
            if (record.TryGetUnicodeString("Direction", out Direction))
            {
                //Console.WriteLine(data);

            }
            if (record.TryGetUnicodeString("SourceAddress", out sip))
            {
               // Console.WriteLine(data);

            }
            if (record.TryGetUnicodeString("DestAddress", out dip))
            {
                ///Console.WriteLine(data);

            }
            if (record.TryGetUInt32("ProcessID", out processid)) //Event ID 500
            {
                //var p = Process.GetProcessById((int)processid);
                //data = p.ProcessName;
                // var p1 = Process.GetProcessById((int)processid).Parent().Id;
                //   pprocessid = ((uint)p1);
                //pprocessid = 0;
				Process p1 = ParentProcessUtilities.GetParentProcess((int)processid);
                pprocessid = (uint)p1.Id;
                var p = Process.GetProcessById((int)pprocessid);
                pdata = p.ProcessName;
            }


            bool foundiname = false;
            bool foundpiname = false;
            Guid foundinameid = Guid.Empty;
            Guid foundpinameid = Guid.Empty;
            bool foundsipaddress = false;
            Guid foundsipid = Guid.Empty;
            Guid founddipid = Guid.Empty;

            bool founddipaddress = false;

            foreach (CProcessId prid in mydata.xImageName)
            {
                if (prid.foundCIprocessName(data))
                {
                    foundiname = true;
                    foundinameid = prid.searchCIprocessName(data);
                    prid.NodeCnt++;
                    break;
                }
            }

            if (foundiname == false)
            {

                foreach (CProcessId prid in mydata.xImageName)
                {
                    if (prid.foundCIprocessName(pdata))
                    {
                        foundpiname = true;
                        foundpinameid = prid.NodeId;
                        //prid.NodeCnt++;
                        break;
                        //  foundinameid = prid.searchCIprocessName(data); 
                    }
                }

                if(foundpiname == false)
                {
                    CProcessId cpimage = new CProcessId(pprocessid, 0, 0, pdata,"Empty");
                    foundpinameid = cpimage.NodeId;
                    mydata.xImageName.Add(cpimage);

                }

                CProcessId cimage = new CProcessId(processid, pprocessid, 0, data, "Empty");
                mydata.xImageName.Add(cimage);


                Relationship trelation1 = new Relationship(foundpinameid, cimage.NodeId, "Parent", "ImageName", "ImageName");
                mydata.Relationships.Add(trelation1);


            }

            foreach (CIpAddress iip in mydata.CIps)
            {
                // Console.WriteLine(iip.getCIpAddress());

                if (iip.foundCIpAddress(sip))
                {
                    foundsipaddress = true;
                    foundsipid = iip.searchCIpAddress(sip);
                    iip.NodeCnt++;
                    break;
                }
            }

            foreach (CIpAddress iip in mydata.CIps)
            {
                // Console.WriteLine(iip.getCIpAddress());

                if (iip.foundCIpAddress(dip))
                {
                    founddipaddress = true;
                    founddipid = iip.NodeId;
                    iip.NodeCnt++;
                    break;

                }
            }
            if (foundsipaddress == false)
            {
                CIpAddress cip = new CIpAddress(sip, foundinameid.ToString());
                mydata.CIps.Add(cip);


            }
            if (founddipaddress == false)
            {
                CIpAddress cip = new CIpAddress(dip, foundinameid.ToString());
                mydata.CIps.Add(cip);


            }

            Relationship trelation2 = new Relationship(foundsipid, foundinameid, "Inbound", "IPAddress", "ImageName");
            mydata.Relationships.Add(trelation2);
            Relationship trelation3 = new Relationship(foundinameid, founddipid, "Connect", "ImageName", "IPAddress");
            mydata.Relationships.Add(trelation3);


        }

        static void OnProcessEvent(IEventRecord record)
        {

            string data = string.Empty;
            string imagedata = string.Empty;
            string cdata = string.Empty;
            string cdatafordll = string.Empty;
            string pdata = string.Empty;
            string pcdata = string.Empty;
            UInt32 praddlength;
            UInt32 imagechecksum;
            UInt32 ppraddlength;
            String username = String.Empty;
            Guid foundprocessnameid = Guid.Empty;
            Guid usernameid = Guid.Empty;
            Guid Event5processNodeId = Guid.Empty;
            UInt32 temp=0;
                 UInt32 timedatestamp=0;
            byte[] bytepeeraddlength = new byte[64];
            String imagebase = String.Empty;
            String imagesize = String.Empty;
            UInt32 imageloadtimestamp = 0;
            //String username = String.Empty;

            if (record.Id == 1) // "A user right was adjusted."
            {

                if (record.TryGetUnicodeString("ImageName", out data))
                {
                    //Console.WriteLine("process " + data);
                    cdata = DevicePathMapper.FromDevicePath(data);
                   
                    cdata = cdata.ToLower();
                    //Console.WriteLine("process " + cdata);
                }

                if (record.TryGetUInt32("ProcessID", out praddlength)) //Event ID 500
                {
                    
                    
                }


                if (record.TryGetUInt32("ParentProcessID", out ppraddlength)) //Event ID 500
                {
                    try
                    {
                        pcdata = myprocess4j.inverse_process_pid_map[ppraddlength];
                    }
                    catch
                    {
                        pdata = ppraddlength.ToString();
                        pcdata = ppraddlength.ToString();
                    }

                   
                }

                // Add process name to PID mapping
                try
                {
                    myprocess4j.inverse_process_pid_map.Add(praddlength, cdata);

                }
                catch
                {
                    myprocess4j.inverse_process_pid_map[praddlength] =  cdata;

                }

                bool foundiname = false;
                bool foundpiname = false;
                Guid foundinameid = Guid.Empty;
                Guid foundpinameid = Guid.Empty;

                if (myprocess4j.process_dict.ContainsKey(cdata))
                {

                    foundiname = true;
                    foundinameid = myprocess4j.process_dict[cdata];
                    myprocess4j.process_pid_map[cdata] = (uint)praddlength;
                    myprocess4j.process_parent_map[praddlength] = (uint)ppraddlength;

                }
                else
                {
                      try
                      {
                         myprocess4j.process_pid_map[cdata] = (uint)praddlength;
                         myprocess4j.process_parent_map[praddlength] = (uint)ppraddlength;
                       

                    }
                      catch
                      {

                      }
                }
                if (myprocess4j.process_dict.ContainsKey(pcdata))
                {
                    foundpiname = true;
                    foundpinameid = myprocess4j.process_dict[pcdata];
                    myprocess4j.process_pid_map[pcdata] = (uint)ppraddlength;

                }
                else
                { 
                    try
                    {
                        myprocess4j.process_pid_map[pcdata] = (uint)ppraddlength;
                    
                    }
                    catch
                    {


                    }

                }

                if (foundpiname == false)
                {
                    //add parent process
                    CProcessId cimage1 = new CProcessId(ppraddlength, 0, 0, pcdata, "Empty");
                    mydata.xImageName.Add(cimage1);
                    foundpinameid = cimage1.NodeId;
                    try
                    {
                        myprocess4j.process_dict.Add(pcdata, cimage1.NodeId);
                        myprocess4j.process_pid_map.Add(pcdata, ppraddlength);

                    }
                    catch { }

                    Process[] processCollection1 = Process.GetProcesses();
                    foreach (Process p in processCollection1)
                    {
                        //cdata = p.MainModule.FileName;
                        if (ppraddlength == (uint)p.Id)
                        {
                            username = ProcessExtensions.GetProcessUser(p);
                            break;
                        }
                    }
                    foreach (User cuser in mydata.Users)
                    {
                        if (cuser.cUser == username)
                        {
                            usernameid = cuser.UserNodeId;

                            break;
                        }
                    }
                    Program.mutex.WaitOne();

                    bool RelationshipExists = false;

                    foreach (Relationship crel in mydata.Relationships)
                    {

                        if (crel.StartNodeId == usernameid && crel.EndNodeId == foundpinameid)
                        {
                            crel.AccessCount++;
                            RelationshipExists = true;
                        }

                    }

                    if (!RelationshipExists)
                    {

                        Relationship trelation1 = new Relationship(usernameid, foundpinameid, "Created", "User", "ImageName");
                        mydata.Relationships.Add(trelation1);
                    }

                    Program.mutex.ReleaseMutex();
                }

                if (foundiname == false)
                {

                    CProcessId cimage2 = new CProcessId(praddlength, ppraddlength, 0, cdata, "Empty");
                    foundinameid = cimage2.NodeId;
                    mydata.xImageName.Add(cimage2);
                    try
                    {
                        myprocess4j.process_dict.Add(cdata, cimage2.NodeId);
                        myprocess4j.process_pid_map.Add(cdata, praddlength);
                        myprocess4j.process_parent_map.Add(praddlength, ppraddlength);
                    }
                    catch { }

                    Process[] processCollection1 = Process.GetProcesses();
                    foreach (Process p in processCollection1)
                    {
                        //cdata = p.MainModule.FileName;
                        if (ppraddlength == (uint)p.Id)
                        {
                            username = ProcessExtensions.GetProcessUser(p);
                            break;
                        }
                    }
                    foreach (User cuser in mydata.Users)
                    {
                        if (cuser.cUser == username)
                        {
                            usernameid = cuser.UserNodeId;

                            break;
                        }
                    }

                    bool RelationshipExists = false;


                    Program.mutex.WaitOne();

                    foreach (Relationship crel in mydata.Relationships)
                    {

                        if (crel.StartNodeId == usernameid && crel.EndNodeId == foundinameid)
                        {
                            crel.AccessCount++;
                            RelationshipExists = true;
                        }

                    }

                    if (!RelationshipExists)
                    {
                        Relationship trelation1 = new Relationship(usernameid, foundinameid, "Created", "User", "ImageName");
                        mydata.Relationships.Add(trelation1);
                    }
                    Program.mutex.ReleaseMutex();

                    //Relationship trelation1 = new Relationship(foundpinameid, cimage.NodeId, "Parent", "ImageName", "ImageName");
                    // mydata.Relationships.Add(trelation1);
                }

            }
            if (record.Id == 15) // "A user right was adjusted."
            {
                //Console.WriteLine($"{record.ProviderId} provider={record.ProviderName}");
            }
            if (record.Id == 5) // "A user right was adjusted."
            {
                Boolean valueExists = false;
               // Console.WriteLine($"{record.ProviderId} provider={record.ProviderName}");
                if (record.TryGetUnicodeString("ImageName", out imagedata))
                {
                    
                    cdata = DevicePathMapper.FromDevicePath(imagedata);
                    cdatafordll = cdata;
                    cdata = cdata.ToLower();
                    try
                    {
                        temp = myprocess4j.process_pid_map[cdata];
                        ImageLoadProcessId = temp;
                        ImageLoadProcessName = cdata;

                    }
                    catch
                    {
                        temp = 0;

                    }

                      //Console.WriteLine("cdata is :" + imagedata + "temp process id is :" + temp );
                }
                if (record.TryGetUInt32("ProcessID", out praddlength)) //Event ID 500
                {
                    // Process p1 =  Process.GetProcessById((int)praddlength);
                    //pdata = p1.MainModule.FileName;

                    //Console.WriteLine(praddlength.ToString());
                    try
                    {
                       // Console.WriteLine("record 5 process name is" + myprocess4j.inverse_process_pid_map[praddlength]);
                        if (ImageLoadProcessId == praddlength && (temp != 0))
                        {
                            Event5processNodeId = myprocess4j.process_dict[cdata];
                            ImageLoadientry = true;
                        }
                        else
                        {
                            ImageLoadientry = false;
                            //Event5processNodeId = myprocess4j.process_dict[ImageLoadProcessName];
                            Event5processNodeId = myprocess4j.process_dict[myprocess4j.inverse_process_pid_map[praddlength]];

                        }
                    }
                    catch
                    {
                        Event5processNodeId = Guid.Empty;
                        Console.WriteLine("process id is empty " + praddlength.ToString());
                    }
                    
                    //Console.WriteLine("Event5processNodeId is :" + Event5processNodeId);
                  
                }
                if (record.TryGetUInt32("ImageCheckSum", out imagechecksum)) //Event ID 500
                {
                   

                }
                if (record.TryGetUInt32("TimeDateStamp", out imageloadtimestamp)) //Event ID 500
                {
                  

                }
                if (record.TryGetBinary("ImageBase", out bytepeeraddlength)) //Event ID 500

                {
                   
                    imagebase = TotalPrintByteArray(bytepeeraddlength);
                  

                }
                if (record.TryGetBinary("ImageSize", out bytepeeraddlength)) //Event ID 500
                {
                  
                    imagesize= TotalPrintByteArray(bytepeeraddlength);                  

                }

                bool foundiname = false;
                Guid foundinameid = Guid.Empty;

                foreach (CImage prid in mydata.xImgLoad)
                {
                    //if (prid.foundCIprocessId(praddlength))
                    if (prid.foundCImageName(cdata))
                    {
                            
                        foundiname = true;
                        foundinameid = prid.NodeId;
                        prid.NodeCnt++;
                        prid.processId = praddlength;
                        prid.ImageChecksum = imagechecksum;
                        prid.imagesize = imagesize;
                        prid.imagebase = imagebase;
                        prid.dt = imageloadtimestamp.ToString();

                        break;
                        //  foundinameid = prid.searchCIprocessName(data); 
                    }
                }

                if (foundiname == false)
                {
                    //Event5processNodeId = myprocess4j.process_dict[cdata];
                    CImage cimage = new CImage(praddlength, imagechecksum, cdata,imagesize,imagebase,imageloadtimestamp);
                    mydata.xImgLoad.Add(cimage);
                    foundinameid = cimage.NodeId;

                    //Console.WriteLine("added image load");
                }
                else
                {

                }

                //Console.WriteLine("imageload " + cdata + "foundinameid " + foundinameid);

                bool RelationshipxExists = false;
                /*
                foreach (Relationship crel in mydata.Relationships)
                {

                    if(crel.StartNodeId == Event5processNodeId && crel.EndNodeId == foundinameid)
                    {
                        crel.AccessCount++;
                        RelationshipxExists = true;
                        break;
                    }

                }
                */
                /*
                if (!RelationshipExists)
                {
                    Relationship trelation1 = new Relationship(Event5processNodeId, foundinameid, "ImageLoad", "ImageName", "ImageLoadName");
                    mydata.Relationships.Add(trelation1);
                }
                */
               

                if (IsDllFile(cdata))
               {
                        bool founddllname = false;
                        string tfilename = Path.GetFileName(cdata);
                        string tfullpath = "C:\\Windows\\System32\\" +  tfilename;
                        bool bExist = System.IO.File.Exists(tfullpath);
                        Guid TdllreaderNodeId = Guid.Empty;

                       //Console.WriteLine("cdata and bexist :" + tfullpath + " " + bExist);
                       
                    if (!bExist)
                    {

                        //string tdlltstring = Event5processNodeId.ToString() + ";" + foundinameid.ToString();
                        //RelationshipxExists = myprocess4j.relation_dict.ContainsKey(rstring);

                        foreach (TDllReaderFunc prid in mydata.tdllfunc)
                        {
                            if (prid.foundDllFunc(cdata))
                            {
                                founddllname = true;
                                TdllreaderNodeId = prid.NodeId;
                                break;
                            }
                        }

                        if (!founddllname)
                        {
                            Process dllexporter = new Process();
                            string arguments = "/from_files " + "\"" + cdatafordll + "\"" + " /scomma \"C:\\ntt\\dllex.csv\"";
                            dllexporter.StartInfo.FileName = "D:\\DFS\\dllexp-x64\\dllexp.exe";
                            dllexporter.StartInfo.Arguments = arguments;
                            // Console.WriteLine("cdata and bexistz :" + arguments);
                            dllexporter.Start();
                            dllexporter.WaitForExit();

                            //            DllReader.ReadFromFile(cdata, foundinameid);

                            try
                            {
                                string[] lines = System.IO.File.ReadAllLines("C:\\ntt\\dllex.csv");
                                foreach (string line in lines)
                                {
                                    string[] columns = line.Split(',');
                                    foreach (string column in columns)
                                    {
                                        //Console.WriteLine($"{column}");
                                        Program.mutex.WaitOne();
                                        bool dllfuncexist = false;
                                        Guid dllfuncnodeid = Guid.Empty;

                                        foreach (TDllReaderFunc prid in mydata.tdllfunc)
                                        {
                                            if (prid.Name == column)
                                            {
                                                dllfuncexist = true;
                                                dllfuncnodeid = prid.NodeId;
                                                prid.NodeCnt++;
                                                break;
                                            }
                                        }

                                        if (dllfuncexist)
                                        {

                                        }
                                        else
                                        {
                                            Program.TDllReaderFunc cDllReader = new Program.TDllReaderFunc(column, cdata);
                                            Program.mydata.tdllfunc.Add(cDllReader);
                                            dllfuncnodeid = cDllReader.NodeId;
                                        }

                                        string dlrstring = foundinameid.ToString() + ";" + dllfuncnodeid.ToString();

                                        if (!myprocess4j.relation_dict.ContainsKey(dlrstring))
                                        {
                                            Program.Relationship trelationdd = new Program.Relationship(foundinameid, dllfuncnodeid, "Export", "ImageLoadName", "DllFunc");
                                            Program.mydata.Relationships.Add(trelationdd);


                                            myprocess4j.relation_dict.Add(dlrstring, "Export");
                                            myprocess4j.relation_count.Add(dlrstring, 1);
                                        }
                                        else
                                        {
                                            myprocess4j.relation_count[dlrstring] = myprocess4j.relation_count[dlrstring] + 1;

                                        }

                                        Program.mutex.ReleaseMutex();
                                        // string tdllstring = column + cdata;
                                        // myprocess4j.tdllfunc_dict.Add(tdllstring, cDllReader.NodeId);


                                        break;
                                    }
                                }
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("The File could not be read:");
                                Console.WriteLine(e.Message);

                                // Console.ReadLine();
                            }

                        }
                        else
                        {
                            string dlrstring = foundinameid.ToString() + ";" + TdllreaderNodeId.ToString();

                            myprocess4j.relation_count[dlrstring] = myprocess4j.relation_count[dlrstring] + 1;

                            /*
                            foreach (Relationship crel in mydata.Relationships)
                            {

                                if (crel.StartNodeId == foundinameid && crel.EndNodeId == TdllreaderNodeId)
                                {
                                    //crel.AccessCount++;
                                    crel.setAccessCount();
                                    break;
                                }

                            }
                            */
                        }
                    }
               }
                /*

                foreach (Relationship crel in mydata.Relationships)
                {
                    
                    if (crel.getStartNodeId() == Event5processNodeId && crel.getEndNodeId() == foundinameid)
                    {
                       // crel.AccessCount++;
                       
                        RelationshipxExists = true;
                        break;
                    }
                    break;

                }
                */
                string rstring = Event5processNodeId.ToString() + ";"   + foundinameid.ToString();
                RelationshipxExists = myprocess4j.relation_dict.ContainsKey(rstring);

                
                if (!RelationshipxExists)
                {
                    Program.mutex.WaitOne();
                    Relationship trelation1 = new Relationship(Event5processNodeId, foundinameid, "ImageLoad", "ImageName", "ImageLoadName");
                    mydata.Relationships.Add(trelation1);
                    myprocess4j.relation_dict.Add(rstring, "ImageLoad");
                    myprocess4j.relation_count.Add(rstring, 1);
                    Program.mutex.ReleaseMutex();
                }
                else
                {
                        myprocess4j.relation_count[rstring] = myprocess4j.relation_count[rstring] + 1;

                                       /*
                    foreach (Relationship crel in mydata.Relationships)
                    {

                        if (crel.getStartNodeId() == Event5processNodeId && crel.getEndNodeId() == foundinameid)
                        {
                            crel.setAccessCount();

                            //RelationshipxExists = true;
                            break;
                        }
                       

                    }*/
                }


                //}


            }

        }

        static bool IsDllFile(string filePath)
        {
            string fileExtension = Path.GetExtension(filePath);
            return string.Equals(fileExtension, ".dll", StringComparison.OrdinalIgnoreCase);
        }

        static string PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("");
            int i = 0;
            // Hack discard 1 st 4 bytes and last 8 bytes
            foreach (var b in bytes)
            {
                if(i > 3 && i < 8)
                {
                    if (i != 7)
                        sb.Append(b + ".");
                    else
                        sb.Append(b);
                }
                i++;
            }
            //sb.Append("}");
            return(sb.ToString());
        }

        static string TotalPrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("");
            int i = 0;
            // Hack discard 1 st 4 bytes and last 8 bytes
            foreach (var b in bytes)
            {
               // if (i > 0 && i < 8)
              //  {
                 //   if (i != 7)
                 //       sb.Append(b + ".");
                 //   else
                        sb.Append(b);
               // }
                //i++;
            }
            //sb.Append("}");
            return (sb.ToString());
        }
        static void OnSMBEvent(IEventRecord record)
        {

            string data = string.Empty;
            UInt32 peeraddlength;
            Guid connguid;
            string myip;
            IPAddress ipv4Addr, ipv6Addr;

            bool foundShare = false;
            Guid foundShareid = Guid.Empty;

            bool foundipaddress = false;
            Guid foundipid = Guid.Empty;

            if (record.TryGetUnicodeString("ShareName", out data)) //600
            {
                    byte[] conntest = new byte[128];
                    record.TryGetBinary("ConnectionGUID", out conntest);
                    connguid = new Guid(conntest);

         
                    foreach (ShareNames iShare in mydata.CShareNames)
                    {
                        if (iShare.foundShareName(data))
                        {
                            foundShare = true;
                            foundShareid = iShare.searchShareName(data);
                            iShare.NodeCnt++;
                            break;
                        }
                    }

                    if (foundShare == false)
                    {
                        ShareNames cshare = new ShareNames(data, connguid);
                        mydata.CShareNames.Add(cshare);
                        foundShareid = cshare.NodeId;
                    }

                    foreach (CIpAddress iip in mydata.CIps)
                    {
                       if (iip.foundCIpAddress(shareipentry))
                       {
                                foundipid = iip.NodeId;
                                shareentry = 0;
                                break;
                       }
                    }

                    int relationshippresent = 0;
                    foreach (Relationship iip in mydata.Relationships)
                    {

                            if (iip.foundsid(foundShareid) && iip.founddid(foundipid))
                            {
                                iip.AccessCount++;
                                relationshippresent = 1;
                                break;

                            }
                    }

                    if (relationshippresent == 0)
                    {
                            Relationship trelation1 = new Relationship(foundipid, foundShareid, "Accessed", "IPAddress", "ShareName");
                            mydata.Relationships.Add(trelation1);
                            shareentry = 0;
                    }
            }
            else if (record.TryGetUInt32("AddressLength", out peeraddlength)) //Event ID 500
            {

                        byte[] bytepeeraddlength = new byte[peeraddlength];
                        if (record.TryGetBinary("Address", out bytepeeraddlength))
                        {


                            myip = PrintByteArray(bytepeeraddlength);
                            //Console.WriteLine(myip);

                            foreach (CIpAddress iip in mydata.CIps)
                            {
                
                                if (iip.foundCIpAddress(myip))
                                {
                                    foundipaddress = true;
                                    foundipid = iip.NodeId;
                                    iip.NodeCnt++;
                                    break;

                                }
                            }

                            byte[] conntest = new byte[128];

                            record.TryGetBinary("ConnectionGUID", out conntest);
                            connguid = new Guid(conntest);

                            if (foundipaddress == false)
                            {
                                CIpAddress cip = new CIpAddress(myip, connguid.ToString());
                                mydata.CIps.Add(cip);
                                foundipid = cip.NodeId;
                                Relationship trelation1 = new Relationship(foundipid, startingGlobalNodeId, "received", "IPAddress", "Computer");
                                mydata.Relationships.Add(trelation1);
                                shareentry = 1;
                            }
                            shareipentry = myip;


                }
            }
            
            
        }



        /// <summary>
        /// Event 7937's payload is basically a big well-formatted string.
        /// We have to parse it by hand, breaking out the interesting bits.
        /// Fortunately, interesting bits are separated by \n\r so we can break
        /// up the parsing by line.
        /// </summary>
        /// <param name="record"></param>
        static void OnEvent(IEventRecord record)
        {
            string data = string.Empty;
            if (!record.TryGetUnicodeString("ContextInfo", out data))
            {
                Console.WriteLine("Could not parse 'ContextInfo' from PowerShell event");
                return;
            }

            var startIndex = 0;


            // The order these keys are parsed in is static. There is no
            // guarantee, however, that future Windows versions won't change
            // the order. This is confirmed to work in:
            //  - Windows 10
            //  - Windows Server 2016
            //  - Windows 8.1
            //  - Windows Server 2012 R2
            var index = data.IndexOf(HostAppKey, startIndex);
            var host = index != -1
                        ? ReadToNewline(data, index + HostAppKey.Length, out startIndex)
                        : string.Empty;

            index = data.IndexOf(CmdNameKey, startIndex);
            var name = index != -1
                        ? ReadToNewline(data, index + CmdNameKey.Length, out startIndex)
                        : string.Empty;

            index = data.IndexOf(CmdTypeKey, startIndex);
            var type = index != -1
                        ? ReadToNewline(data, index + CmdTypeKey.Length, out startIndex)
                        : string.Empty;

            index = data.IndexOf(UserNameKey, startIndex);
            var user = index != -1
                        ? ReadToNewline(data, index + UserNameKey.Length, out startIndex)
                        : string.Empty;



            bool founduser = false;
            Guid founduserid = Guid.Empty;

            foreach (User iuser in mydata.Users)
            {
                if (iuser.founduser(user))
                {
                    founduser = true;
                    founduserid = iuser.searchuser(user);
                    iuser.NodeCnt++;
                    break;
                }
            }

            bool foundmethod = false;
            Guid foundmethodid = Guid.Empty;

            foreach (Method iMethod in mydata.Methods)
            {
                if (iMethod.foundmethod(name))
                {
                    foundmethod = true;
                    foundmethodid = iMethod.searchmethod(name);
                    iMethod.NodeCnt++;
                    break;
                }
            }


            if (founduser == false)
            {

                //Method mydb = new MypowershellDB(user, "pETW", DateTime.Now.ToString(@"MM\/dd\/yyyy h\:mm tt"), name);

                User tuser = new User(user);
                founduserid = tuser.searchuser(user);
                mydata.Users.Add(tuser);
                Relationship trelation1 = new Relationship(startingGlobalNodeId, founduserid, "has", "Computer", "User");
                mydata.Relationships.Add(trelation1);
            }

            
            if (foundmethod == false)
            {
                Guid usernodeid = founduserid;

                Method tmethod = new Method(name);

                mydata.Methods.Add(tmethod);
                foundmethodid = tmethod.searchmethod(name);

                //Relationship trelation = new Relationship(usernodeid, tmethod.searchmethod(name), "invokes", "User", "Method");

                //mydata.Relationships.Add(trelation);

            }

            if (founduser == true && foundmethod == true)
            {

            }
            else
            { 
                Relationship trelation = new Relationship(founduserid, foundmethodid, "invokes", "User", "Method");
                mydata.Relationships.Add(trelation);
            }
            




        }


        public static string ReadToNewline(string data, int index, out int newIndex)
        {
            if (index >= data.Length)
            {
                newIndex = index;
                return string.Empty;
            }

            if (index < 0) index = 0;

            var start = index;

            while (index < data.Length && data[index] != '\r') index++;

            newIndex = index;
            return data.Substring(start, index - start);
        }




    }


}
