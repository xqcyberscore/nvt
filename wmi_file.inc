###############################################################################
# OpenVAS Vulnerability Test Library functions
# $Id: wmi_file.inc 10110 2018-06-07 09:04:19Z cfischer $
#
# WMI Client Functions for Directories and Files
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 10110 $
#
###############################################################################


##############################################################################
# CLASS: win32_Directory Functions
#
# - wmi_file_subdir              - Returns List of all sub directories
# - wmi_file_check_dir_exists    - Return value as 1 if exists else 0
# - wmi_file_is_subdir_readable  - Lists readable rights of sub directories.
# - wmi_file_is_subdir_writeable - Lists writeable rights of sub directories.
#
##############################################################################

# Ex: dirPath = "\\Program Files\\"
function wmi_file_subdir(handle, dirPath)
{
  if(dirPath){
    query = 'Select Name from Win32_Directory Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);
  }
  else return(0);

  pathList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< pathList) || !pathList){
    return(0);
  }

  return pathList;
}

# Ex: dirPath = "C:\\windows\\"
function wmi_file_check_dir_exists(handle, dirPath)
{
  if(dirPath){
    query = 'Select Caption from Win32_Directory Where Name = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);
  }
  else return(0);

  dirList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< dirList) || !dirList){
    return(0);
  }

  return(1);
}


# Ex: dirPath = "\\windows\\"
function wmi_file_is_subdir_readable(handle, dirPath)
{
  if(dirPath){
    query = 'Select Readable from Win32_Directory Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);
  }
  else return(0);

  dirList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< dirList) || !dirList){
    return(0);
  }

  dirList = ereg_replace(pattern:"\|", string:dirList, replace:" - ");
  return dirList;
}

# Ex: dirPath = "\\windows\\"
function wmi_file_is_subdir_writeable(handle, dirPath)
{
  if(dirPath){
    query = 'Select Writeable from Win32_Directory Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);
  }
  else return(0);

  dirList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< dirList) || !dirList){
    return(0);
  }

  dirList = ereg_replace(pattern:"\|", string:dirList, replace:" - ");
  return dirList;
}

#############################################################################
# CLASS: CIM_DataFile/Win32_ShortcutFile Functions
#
# - wmi_file_filelist          - Queries List of all files under directory.
# - wmi_file_filesize          - Gets the size of file.
# - wmi_file_extnfile          - Returns List of extension files under directory.
# - wmi_file_check_file_exists - Returns 1 if file exsits else 0
# - wmi_file_filesearch        - Returns Files based on product.
# - wmi_file_fileinfo          - Extracts all properties and description of file.
# - wmi_file_fileversion       - Gets version of the file.
# - wmi_file_filecreationdate  - Returns creation date of the file.
# - wmi_file_filemodifieddate  - Returns file's Last modified date.
# - wmi_file_is_file_readable  - True for all readable file(s).
# - wmi_file_is_file_writeable - True for all writeable file(s).
#
##############################################################################

# Ex: dirPath = "\\Windows\\"
function wmi_file_filelist(handle, dirPath)
{
  if(dirPath){
    query = 'Select Name from CIM_DataFile Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);
  }
  else return(0);

  fileList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileList) || !fileList){
    return(0);
  }

  return fileList;
}

# Ex: filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_filesize(handle, filePath)
{
  if(filePath){
    query = 'Select FileSize from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  fileList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileList) || !fileList){
    return(0);
  }

  fileList = ereg_replace(pattern:"\|[.:0-9a-zA-Z \\]+", string:fileList, replace:"");
  return fileList;
}

# Ex: dirPath = "\\Windows\\" and fileExtn ="exe"
function wmi_file_get_extnfile(handle, dirPath, fileExtn)
{
  if(dirPath && fileExtn){
    query = 'Select Name from CIM_DataFile Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22) +
             'and Extension = ' + raw_string(0x22) + fileExtn + raw_string(0x22);
  }

  else if(fileExtn){
    query = 'Select Name from CIM_DataFile Where Extension = ' +
             raw_string(0x22) + fileExtn + raw_string(0x22);
  }

  else return(0);

  fileExtn = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileExtn) || !fileExtn){
    return(0);
  }

  return fileExtn;
}

# Ex: filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_check_file_exists(handle, filePath)
{
  if(filePath){
    query = 'Select Name from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  fileList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileList) || !fileList){
    return(0);
  }

  return(1);
}

# Ex: dirPath = "\\WINDOWS\\" and fileName = "Safari" and fileExtn = "exe"
function wmi_file_file_search(handle, dirPath, fileName, fileExtn)
{
  if(dirPath && fileName && fileExtn){
    query = 'Select Name from CIM_DataFile Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22) +
            'and FileName = ' + raw_string(0x22) + fileName + raw_string(0x22) +
            'and Extension = ' + raw_string(0x22) + fileExtn + raw_string(0x22);
  }
  else if(fileName && fileExtn){
    query = 'Select Name from CIM_DataFile Where FileName = ' +
             raw_string(0x22) + fileName + raw_string(0x22) +
             'and Extension = ' + raw_string(0x22) + fileExtn + raw_string(0x22);
  }
  else if(fileName)
  {
    query = 'Select Name from CIM_DataFile Where FileName = ' +
             raw_string(0x22) + fileName + raw_string(0x22);
  }
  else return(0);

  fileList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileList) || !fileList){
    return(0);
  }

  return fileList;
}

# Ex: filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_fileinfo(handle, filePath)
{
  if(filePath){
    query = 'Select * from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  fileInfo = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileInfo) || !fileInfo){
    return(0);
  }

  return wmi_misc_split_res(List:fileInfo);
}

# Ex filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_fileversion(handle, filePath)
{
  if(filePath){
    query = 'Select Version from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  fileVer = wmi_query(wmi_handle:handle, query:query);

  if((fileVer =~ "NTSTATUS|\(null\)") || !fileVer){
    return(0);
  }

  fileVer = ereg_replace(pattern:"[.:0-9a-zA-Z \\_\-\+]+\|", string:fileVer, replace:"");
  return fileVer;
}

# Ex: filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_filecreationdate(handle, filePath)
{
  if(filePath){
    query = 'Select CreationDate from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  filePath = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< filePath) || !filePath){
    return(0);
  }

  filePath = ereg_replace(pattern:"\|[.:0-9a-zA-Z \\]+", string:filePath, replace:"");
  return filePath;
}

# Ex: filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_filemodifieddate(handle, filePath)
{
  if(filePath){
    query = 'Select LastModified from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  filePath = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< filePath) || !filePath){
    return(0);
  }

  filePath = ereg_replace(pattern:"\|[.:0-9a-zA-Z \\]+", string:filePath, replace:"");
  return filePath;
}

# Ex: dirPath = "\\windows\\" and filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_is_file_readable(handle, dirPath, filePath)
{
  if(dirPath){
    query = 'Select Readable from CIM_DataFile Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);
  }
  else if(filePath){
    query = 'Select Readable from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  fileList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileList) || !fileList){
    return(0);
  }

  fileList = ereg_replace(pattern:"\|", string:fileList, replace:" - ");
  return fileList;
}

# Ex: dirPath = "\\windows\\" and filePath = "c:\\windows\\system32\\cmd.exe"
function wmi_file_is_file_writeable(handle, dirPath, filePath)
{
  if(dirPath){
    query = 'Select Writeable from CIM_DataFile Where Path = ' +
             raw_string(0x22) + dirPath + raw_string(0x22);

  }
  else if(filePath){
    query = 'Select Writeable from CIM_DataFile Where Name = ' +
             raw_string(0x22) + filePath + raw_string(0x22);
  }
  else return(0);

  fileList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< fileList) || !fileList){
    return(0);
  }

  fileList = ereg_replace(pattern:"\|", string:fileList, replace:" - ");
  return fileList;
}
