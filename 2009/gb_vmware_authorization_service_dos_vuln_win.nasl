###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_authorization_service_dos_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# VMware Authorization Service Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
###############################################################################

tag_impact = "Successful exploitation allow attackers to execute arbitrary code
on the affected application and causes the Denial of Service.

Impact Level: Application";

tag_affected = "VMware ACE 2.5.3 and prior.
VMware Player 2.5.3 build 185404 and prior.
VMware Workstation 6.5.3 build 185404 and prior.";

tag_insight = "The vulnerability is due to an error in the VMware Authorization
Service when processing login requests. This can be exploited to terminate
the 'vmware-authd' process via 'USER' or 'PASS' strings containing '\xFF'
characters, sent to TCP port 912.";

tag_solution = "Upgrade VMware ACE to 2.5.4 build 246459 or later,
Upgrade VMware Player to 2.5.4 build 246459 or later,
Upgrade VMware Workstation to 6.5.4 build 246459 or later,
For updates refer to http://www.vmware.com";

tag_summary = "The host is installed with VMWare product(s) that are vulnerable
to Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801027");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3707");
  script_name("VMware Authorization Service Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36988");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1022997.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

# VMware Player
vmpVer = get_kb_item("VMware/Player/Win/Ver");
if(vmpVer)
{
  if(version_in_range(version:vmpVer, test_version:"2.0", test_version2:"2.5.3"))
  {
    security_message(0);
    exit(0);
  }
}

# VMware Workstation
vmwtnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmwtnVer)
{
  if(version_in_range(version:vmwtnVer, test_version:"6.0", test_version2:"6.5.3"))
  {
    security_message(0);
    exit(0);
  }
}

# VMware ACE
aceVer = get_kb_item("VMware/ACE/Win/Ver");
if(aceVer)
{
  if(version_in_range(version:aceVer, test_version:"2.0", test_version2:"2.5.3")){
    security_message(0);
  }
}
