###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftp_explore_dir_traversal_vuln.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# FTPx Corp FTP Explorer Directory Traversal Vulnerability
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

tag_affected = "FTPx Corp FTP Explore version 10.5.19.1 and prior.";

tag_insight = "The flaw exists due to error in handling of file names. It does
not properly sanitise filenames containing directory traversal sequences that
are received from an FTP server.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with FTPx Corp FTP Explorer and is prone to
directory traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902235");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)");
  script_cve_id("CVE-2010-3101");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FTPx Corp FTP Explorer Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40901");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/Aug/51");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2010080016");
  script_xref(name : "URL" , value : "http://osdir.com/ml/bugtraq.security/2010-08/msg00054.html");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/directory_traversal_in_ftp_explorer.html");


  script_tag(name:"qod_type", value:"registry");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\FTP Explorer";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for 3D-FTP Application
ftpVer = registry_get_sz(key:key , item:"Version");
if(ftpVer != NULL)
{
   ## Check for 3D-FTP version less or equal 10.5.19.1
   if(version_is_less_equal(version:ftpVer, test_version:"10.5.19.1")){
     security_message(0) ;
   }
}
