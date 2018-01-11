###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fresh_ftp_client_dir_traversal_vuln.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# FreshWebMaster Fresh FTP Filename Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_impact = "Successful exploitation will allow attackers to download files
to an arbitrary location on a user's system.

Impact Level: Application";

tag_affected = "FreshWebMaster Fresh FTP version 5.37 and prior";

tag_insight = "The flaw is due to an input validation error when downloading
directories containing files with directory traversal specifiers in the
filename.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Fresh FTP Client and is prone to
directory traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801535");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_cve_id("CVE-2010-4149");
  script_bugtraq_id(44072);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreshWebMaster Fresh FTP Filename Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41798/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1010-exploits/freshftp-traversal.txt");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/directory_traversal_vulnerability_in_freshftp.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Get the file content
function read_content(path)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
  radFile = read_file(share:share, file:file, offset:0, count:500);
  return radFile;
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## check application installation
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FreshWebmaster FreshFTP_is1\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get install location
ftpPath = registry_get_sz(key:key, item:"InstallLocation");
if(ftpPath)
{
  ## get the version from license.txt
  ftpPath1  = ftpPath + "\license.txt";
  radFile =  read_content(path:ftpPath1);
  if(isnull(radFile))
  {
     ## get the version from readme.txt
     reamePath = ftpPath + "\readme.txt";
     radFile = read_content(path:ftpPath);
  }

  if(!isnull(radFile))
  {
    ## match the version
    ftpVer = eregmatch(pattern:"FRESHFTP ver ([0-9.]+)", string:radFile, icase:1);
    if(ftpVer[1] != NULL)
    {
      ## Check version less or equal 5.37
      if(version_is_less_equal(version:ftpVer[1], test_version:"5.37")){
        security_message(0) ;
      }
    }
  }
}
