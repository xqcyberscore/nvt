###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftpgetter_pasv_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# FTPGetter 'PASV' Command Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows execution of arbitrary code.

Impact Level: System/Application.";

tag_affected = "FTPGetter version 3.58.0.21 and prior.";

tag_insight = "The flaw is due to a boundary error when reading a log file
using fgets() which can be exploited to cause a stack-based buffer overflow
by tricking a user into connecting to a malicious FTP server and sending a
specially crafted 'PWD' or 'PASV' response.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with FTPGetter FTP Client and is prone to
buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801839");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46120);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FTPGetter 'PASV' Command Remote Stack Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "https://secunia.com/advisories/41857");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16101/");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/46120.py");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

## Confirm Windows OS
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
    ## Get FTPGetter Path
    fgpath = registry_get_sz(key: key + item , item:"DisplayIcon");
    if(!isnull(fgpath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:fgpath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:fgpath);

      ## Check for FTPGetter Version
      fgVer = GetVer(file:file, share:share);
      if(fgVer != NULL)
      {
        ## Check for FTPGetter version 3.58.0.21 and prior
        if(version_is_less_equal(version:fgVer, test_version:"3.58.0.21"))
        {
          security_message(0) ;
          exit(0);
        }
      }
    }
  }
}
