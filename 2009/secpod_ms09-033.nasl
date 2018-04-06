###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-033.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Virtual PC/Server Privilege Escalation Vulnerability (969856)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code with
  escalated privileges on the guest operating system.
  Impact Level: System/Application";
tag_affected = "Microsoft Virtual PC 2004 Service Pack 1 and prior
  Microsoft Virtual PC 2007 Service Pack 1 and prior
  Microsoft Virtual Server 2005 R2 Service Pack 1 and prior";
tag_insight = "The flaw is due to the application not properly validating required
  CPU privilege levels of certain machine instructions running within the guest
  operating system environment.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-033.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-033.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900690");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-15 20:20:16 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1542");
  script_bugtraq_id(35601);
  script_name("Microsoft Virtual PC/Server Privilege Escalation Vulnerability (969856)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35808");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1890");
  script_xref(name : "URL" , value : "ghhttp://www.microsoft.com/technet/security/bulletin/ms09-033.mspx");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\Microsoft\Virtual PC"))
{
  pcPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                           item:"Install Path");
  if(!pcPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:pcPath);
  pcfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                        string:pcPath + "\drivers\VMM.sys");

  pcVer = GetVer(file:pcfile, share:share);
  if(pcVer != NULL)
  {
    # Grep for VMM.sys version 1.1.400.0 < 1.1.465.15 for Virtual PC 2004 SP1
    if(version_in_range(version:pcVer, test_version:"1.1.400.0",
                                       test_version2:"1.1.465.14")){
      security_message(0);
    }
    # Grep for VMM.sys version 1.1.500.0 < 1.1.598.0 for Virtual PC 2007
    else if(version_in_range(version:pcVer, test_version:"1.1.500.0",
                                            test_version2:"1.1.597.0")){
      security_message(0);
    }
    # Grep for VMM.sys version 1.1.600.0 < 1.1.656.0 for Virtual PC 2007 SP1
    else if(version_in_range(version:pcVer, test_version:"1.1.600.0",
                                            test_version2:"1.1.655.0")){
      security_message(0);
    }
    exit(0);
  }
}

if(registry_key_exists(key:"SOFTWARE\Microsoft\Virtual Server"))
{
  srvPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!srvPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:srvPath);
  srvfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:srvPath + "\drivers\VMM.sys");

  srvVer = GetVer(file:srvfile, share:share);
  if(srvVer != NULL)
  {
    # Check for Virtual Server 2005 R2 Service Pack 1 version < 1.1.656.0
    if(version_is_less(version:srvVer, test_version:"1.1.655.0")){
      security_message(0);
    }
  }
}
