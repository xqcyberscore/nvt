###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_tls_ssl_spoofing_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Microsoft Windows TLS/SSL Spoofing Vulnerability (977377)
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

tag_impact = "Successful exploitation could allow remote attackers to prepend content into a
  legitimate, client-initiated request to a server in the context of a valid
  TLS/SSL-authenticated session.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2000 Service Pack 4 and prior
  Microsoft Windows 2003 Service Pack 2 and prior";
tag_insight = "The flaw is due to an error in TLS/SSL, allows a malicious man-in-the-middle
  attack to introduce and execute a request in the protected TLS/SSL session
  between a client and a server.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/advisory/977377.mspx";
tag_summary = "This host installed with TLS/SSL protocol which is prone to Spoofing
  Vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800466");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_name("Microsoft Windows TLS/SSL Spoofing Vulnerability (977377)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/977377");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0349");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/977377.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check for Hotfix Missing 977377
if(hotfix_missing(name:"977377") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Schannel.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Schannel.dll version < 5.1.2195.7371
  if(version_is_less(version:sysVer, test_version:"5.1.2195.7371")){
    security_message(0);
  }
}

# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Schannel.dll < 5.1.2600.3664
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3664")){
      security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Schannel.dll <  5.1.2600.5931
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5931")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Schannel.dll version < 5.2.3790.4657
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4657")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
