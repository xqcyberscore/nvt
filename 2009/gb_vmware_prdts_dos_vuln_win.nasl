###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_dos_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# VMware Products vmware-authd Denial of Service Vulnerability (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker deny virtual machines
  access to local users.
  Impact Level : Application";

tag_solution = "Solution/Patch not available as on 4th February 2009. For further
  updates refer the below URLs.
  http://www.vmware.com/download/ws
  http://www.vmware.com/download/player";


tag_summary = "The host is installed with VMWare product(s) that are vulnerable
  to Denial of Service vulnerability.";

tag_affected = "VMware Player version 2.5.1 or prior on Windows.
  VMware Workstation version 6.5.1 or prior on Windows.";
tag_insight = "VMware product(s) throws an error in the vmware-authd daemon when processing
  overly long strings. This will terminate the vmware-authd process via an
  overly long 'USER' or 'PASS' strings sent to TCP port 912.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800410");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0177");
  script_bugtraq_id(33095);
  script_name("VMware Products vmware-authd Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7647");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33372");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0024");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jan/1021512.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
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
  if(version_is_less_equal(version:vmplayerVer, test_version:"2.5.1"))
  {
    security_message(0);
    exit(0);
  }
}

# VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(version_is_less_equal(version:vmworkstnVer, test_version:"6.5.1")){
    security_message(0);
  }
  exit(0);
}
