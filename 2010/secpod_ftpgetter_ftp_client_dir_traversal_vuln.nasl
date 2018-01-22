###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftpgetter_ftp_client_dir_traversal_vuln.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# FTPGetter FTP Client Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to write files into
a user's Startup folder to execute malicious code when the user logs on.

Impact Level: Application.";

tag_affected = "FTPGetter FTP Client 3.51.0.05 and prior.";

tag_insight = "The flaw exists due to error in handling of certain crafted file
names. It does not properly sanitise filenames containing directory traversal
sequences that are received from an FTP server.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with FTPGetter FTP Client and is prone to
directory traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902233");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)");
  script_cve_id("CVE-2010-3103");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FTPGetter FTP Client Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41069");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/directory_traversal_in_ftpgetter.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  fgName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("FTPGetter" >< fgName)
  {
    ## Check for FTPGetter FTP Client
    fgpath = registry_get_sz(key: key + item , item:"DisplayIcon");
    if(!isnull(fgpath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:fgpath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:fgpath);

      ## Check for FTPGetter FTP Clent File Version
      fgVer = GetVer(file:file, share:share);
      if(fgVer != NULL)
      {
        ## Check for FTPGetter FTP Clent version 3.51.0.05 and prior
        if(version_is_less_equal(version:fgVer, test_version:"3.51.0.05"))
        {
          security_message(0) ;
          exit(0);
        }
      }
    }
  }
}
