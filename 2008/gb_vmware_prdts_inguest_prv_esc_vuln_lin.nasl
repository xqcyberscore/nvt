###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_inguest_prv_esc_vuln_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# VMware Products Trap Flag In-Guest Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allow attackers to execute arbitrary code
  on the affected system and users could bypass certain security restrictions
  or can gain escalated privileges.
  Impact Level : System";

tag_solution = "Upgrade VMware latest versions,
  www.vmware.com/download/ws/
  www.vmware.com/download/player/
  www.vmware.com/download/server/";


tag_summary = "The host is installed with VMWare product(s) that are vulnerable
  to privilege escalation vulnerability.";

tag_affected = "VMware Server 1.x - 1.0.7 on Linux
  VMware Player 1.x - 1.0.8 and 2.x - 2.0.5 on Linux
  VMware Workstation 6.0.5 and earlier on all Linux";
tag_insight = "The issue is due to an error in the CPU hardware emulation while
  handling the trap flag.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800072");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4915", "CVE-2008-4917");
  script_bugtraq_id(32168);
  script_name("VMware Products Trap Flag In-Guest Privilege Escalation Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/3052");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2008-0018.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

# VMware Server
vmserverVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserverVer)
{
  if(version_is_less_equal(version:vmserverVer, test_version:"1.0.7")){
    security_message(0);
  }
  exit(0);
}

# VMware Player
vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer)
{
  if(version_is_less_equal(version:vmplayerVer, test_version:"1.0.8"))
  {
    security_message(0);
    exit(0);
  }
  else if(version_in_range(version:vmplayerVer, test_version:"2.0",
          test_version2:"2.0.5")){
    security_message(0);
  }
  exit(0);
}

# VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer)
{
  if(version_in_range(version:vmworkstnVer, test_version:"5.0",
                      test_version2:"5.5.8"))
  {
    security_message(0);
    exit(0);
  }
  else if(version_in_range(version:vmworkstnVer, test_version:"6.0",
          test_version2:"6.0.5")){
    security_message(0);
  }
  exit(0);
}
