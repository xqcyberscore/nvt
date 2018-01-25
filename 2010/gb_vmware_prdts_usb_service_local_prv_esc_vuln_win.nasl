###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_usb_service_local_prv_esc_vuln_win.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# VMware Products USB Service Local Privilege Escalation Vulnerability (Windows)
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

tag_impact = "Successful exploitation will allow attacker to modify arbitrary memory
  locations in guest kernel memory and gain privileges.
  Impact Level: System/Application";
tag_solution = "Upgrade to Vmware Player 3.0.1 build 227600,
  http://www.vmware.com/products/player/

  upgrade VMware Workstation 7.0.1 build 227600,
  http://www.vmware.com/products/ws/";

tag_affected = "Vmware Player 3.0 before 3.0.1 build 227600,
  VMware Workstation 7.0 before 7.0.1 build 227600 ion windows.";
tag_insight = "The flaw is due to error in 'USB' service which allows host OS users to gain
  privileges by placing a Trojan horse program at an unspecified location on
  the host OS disk.";
tag_summary = "The host is installed with VMWare products and are prone to local
  privilege escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801322");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1140");
  script_bugtraq_id(39397);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Products USB Service Local Privilege Escalation Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39206");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2010-04/0121.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_require_keys("VMware/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

# Check for VMware Player
vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer != NULL )
{
  if(version_is_equal(version:vmplayerVer, test_version:"3.0.0"))
  {
    security_message(0);
    exit(0);
  }
}

#Check for VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer != NULL)
{
  if(version_is_equal(version:vmworkstnVer, test_version:"7.0.0")){
    security_message(0);
  }
}
