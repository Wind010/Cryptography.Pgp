
using System;
using System.IO;

namespace Cryptography.Common
{
    public class FileHandler : IFileHandler
    {
        public string FileName { get; }

        public FileHandler(string fileName)
        {
            FileName = fileName;
        }

        public string ReadFile()
        {
            using (var streamReader = File.OpenText(FileName))
            {
                return streamReader.ReadToEnd();
            }
        }

        public Byte[] ReadEncryptedFile()
        {
            Byte[] encryptedBytes;
            using (var fileStream = File.OpenRead(FileName))
            {
                encryptedBytes = new Byte[fileStream.Length];
                fileStream.Read(encryptedBytes, 0, (int) fileStream.Length);
            }

            return encryptedBytes;
        }

        public void WriteToFile(string key)
        {
            using (StreamWriter sw = File.CreateText(FileName))
            {
                sw.Write(key);
            }
        }

        public void WriteToFile(byte[] bytes, int offset, int count)
        {
            using (FileStream fs = File.Create(FileName))
            {
                fs.Write(bytes, offset, count);
            }
        }

    }



}
