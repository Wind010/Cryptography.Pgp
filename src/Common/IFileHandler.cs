using System;
using System.Collections.Generic;
using System.Text;

namespace Cryptography.Common
{
    public interface IFileHandler
    {
        string FileName { get; }

        string ReadFile();

        Byte[] ReadEncryptedFile();

        void WriteToFile(string key);

        void WriteToFile(byte[] bytes, int offset, int count);

    }


}
