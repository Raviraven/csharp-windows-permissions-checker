using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace WindowsPermissionChecker
{
    class Program
    {
        /*
         Directories structure:
        bin/Debug
                 /Test
                    /Detail
                    test.txt
         */
        private static string _generalDirectory = "Test";
        private static string _detailDirectory = "Test\\Detail";
        private static string _generalFileName = "";
                
        private static Func<string, string> accessDenied = (path) => { return $"{path} access denied"; };
        private static int writeLogsRights { get { return (int)FileSystemRights.Synchronize + (int)FileSystemRights.Write + (int)FileSystemRights.ReadAndExecute; } }


        static void Main(string[] args)
        {
            checkAccess();
        }


        protected static void hasWriteAccessToFolder(string folderPath)
           => hasWriteAccess((path) => Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)), folderPath);

        protected static void hasWriteAccessToFile(string filePath)
            => hasWriteAccess((path) => File.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)), filePath);

        protected static void hasWriteAccess(Func<string, AuthorizationRuleCollection> getAccessControl, string path)
        {
            var acl = getAccessControl(path);

            var accessRuleList = acl.OfType<FileSystemAccessRule>().Where(r => r.IdentityReference.Value == WindowsIdentity.GetCurrent().Name).ToList();
            var writeAccess = accessRuleList.FirstOrDefault(n => n.AccessControlType == AccessControlType.Allow && (int)n.FileSystemRights >= writeLogsRights);
            var accessDeniedToCurrentUser = accessRuleList.Any(n => n.AccessControlType == AccessControlType.Deny && (int)n.FileSystemRights >= (int)FileSystemRights.Write);

            bool userHasRights = (writeAccess != null && !accessDeniedToCurrentUser) ? true : false;

            if (!userHasRights)
                throw new Exception(accessDenied(path));
        }

        protected static void checkAccess()
        {
            hasWriteAccessToFolder(_generalDirectory);
            hasWriteAccessToFolder(_detailDirectory);

            if (File.Exists($"{_generalDirectory}{_generalFileName}")) hasWriteAccessToFile($"{_generalDirectory}{_generalFileName}");
        }
    }
}