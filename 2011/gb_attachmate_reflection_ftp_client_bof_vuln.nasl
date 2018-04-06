###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_attachmate_reflection_ftp_client_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Attachmate Reflection FTP Client LIST Command Remote Heap Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Upgrade to the latest version or apply the fix,
  For updates refer to http://support.attachmate.com/techdocs/1708.html

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****";

tag_impact = "Successful exploitation will allow attacker to execution of arbitrary code.
  Impact Level: Application";
tag_affected = "Attachmate Reflection 2008
  Attachmate Reflection 2011 R1 before 15.3.2.569
  Attachmate Reflection 2011 R2 before 15.4.1.327
  Attachmate Reflection 14.1 SP1 before 14.1.1.206
  Attachmate Reflection Windows Client 7.2 SP1 before hotfix 7.2.1186";
tag_insight = "The flaw is due to boundary error in the Reflection FTP client in
  rftpcom.dll, which fails to process filenames within a directory listing.";
tag_summary = "This host is installed with Attachmate Reflection FTP Client and
  is prone to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802371");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-5012");
  script_bugtraq_id(50691);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-05 16:57:58 +0530 (Wed, 05 Jan 2011)");
  script_name("Attachmate Reflection FTP Client LIST Command Remote Heap Buffer Overflow Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/46879");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71330");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026340");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18119/");
  script_xref(name : "URL" , value : "http://support.attachmate.com/techdocs/2288.html");
  script_xref(name : "URL" , value : "http://support.attachmate.com/techdocs/2502.html");
  script_xref(name : "URL" , value : "http://support.attachmate.com/techdocs/1708.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get version from Registry
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  refName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Attachmate Reflection" >< refName)
  {
    refVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(refVer != NULL)
    {
      ## Check for version's
      if(version_in_range(version:refVer, test_version:"15.3", test_version2:"15.3.569.0") ||
         version_in_range(version:refVer, test_version:"15.4", test_version2:"15.4.327.0)") ||
         version_in_range(version:refVer, test_version:"7.2", test_version2:"7.2.1163") ||
         version_in_range(version:refVer, test_version:"14.1", test_version2:"14.1.1173"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
