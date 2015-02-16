﻿using EnvDTE;
using System;
using System.ComponentModel.Composition;
using System.IO;
using System.Threading.Tasks;

namespace NuGet.PackageManagement.VisualStudio
{
    [Export(typeof(ICommonOperations))]
    public class VsCommonOperations : ICommonOperations
    {
        private readonly DTE _dte;

        public VsCommonOperations()
            : this(ServiceLocator.GetInstance<DTE>())
        {
        }

        public VsCommonOperations(DTE dte)
        {
            _dte = dte;
        }

        public Task OpenFile(string filePath)
        {
            if (filePath == null)
            {
                throw new ArgumentNullException("filePath");
            }

            if (_dte.ItemOperations != null && File.Exists(filePath))
            {
                Window window = _dte.ItemOperations.OpenFile(filePath);
                return Task.FromResult(0);
            }

            return Task.FromResult(0);
        }
    }
}
