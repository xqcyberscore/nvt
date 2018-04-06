###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_dos_vuln_win_jun09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# VMware Products Descheduled Time Accounting Driver DoS Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to cause denial of
  service to local users.
  Impact Level: Application";
tag_affected = "VMware Server version prior to 2.0.1 build 156745,
  VMware Server version prior to 1.0.9 build 156507,
  VMware Player version prior to 2.5.2 build 156735,
  VMware Workstation version prior to 6.5.2 build 156735 on Windows.";
tag_insight = "The vulnerability is due to an unspecified error within the VMware
  Descheduled Time Accounting driver.";
tag_solution = "Upgrade your VMWares according to the below link,
  http://www.vmware.com/security/advisories/VMSA-2009-0007.html";
tag_summary = "The host is installed with VMWare product(s) and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800805");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1805");
  script_bugtraq_id(35141);
  script_name("VMware Products Descheduled Time Accounting Driver DoS Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35269");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/May/1022300.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/503912/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

# VMware Player
vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  # Check for version < 2.5.2 (2.5.2 build 156735)
  if(version_is_less(version:vmplayerVer, test_version:"2.5.2"))
  {
    security_message(0);
    exit(0);
  }
}

# VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  # Check for version < 6.5.2 (6.5.2 build 156735)
  if(version_is_less(version:vmworkstnVer, test_version:"6.5.2"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for VMware Server
vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer != NULL)
{
  # Check for version 1.0.9 (1.0.9 build 156507) or < 2.0.1 (2.0.1 build 156745)
  if(version_in_range(version:vmserverVer, test_version:"1.0", test_version2:"1.0.8")||
     version_in_range(version:vmserverVer, test_version:"2.0", test_version2:"2.0.0")){
    security_message(0);
  }
}
