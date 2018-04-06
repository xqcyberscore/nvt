###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mult_vuln_win_jun11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# VMware Products Multiple Vulnerabilities (Windows) - jun 11
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Apply the patch or upgrade to player 3.1.4 or later,
  http://www.vmware.com/products/player/
  http://downloads.vmware.com/d/info/desktop_downloads/vmware_player/3_0

  Apply the patch or upgrade to VMware Workstation 7.1.4 or later,
  http://downloads.vmware.com/d/info/desktop_downloads/vmware_workstation/7_0

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to gain privileges on the guest OS.
  Impact Level: Application";
tag_affected = "VMware Player 3.1.x before 3.1.4
  VMware Workstation 7.1.x before 7.1.4 on Windows.";
tag_insight = "Multiple flaws are due to,
  - An information disclosure vulnerability in 'Mount.vmhgfs', allows guest OS
    users to determine the existence of host OS files and directories via
    unspecified vectors.
  - A race condition privilege escalation in 'Mount.vmhgfs' via a race condition,
    that allows guest OS users to gain privileges on the guest OS by mounting a
    file system on top of an arbitrary directory.";
tag_summary = "The host is installed with VMWare product(s) which are vulnerable
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801948");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1787", "CVE-2011-2146");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Products Multiple Vulnerabilities (Windows) - jun 11");

  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2011-0009.html");
  script_xref(name : "URL" , value : "http://lists.vmware.com/pipermail/security-announce/2011/000141.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH,");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
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
  if(version_in_range(version:vmpVer, test_version:"3.1.0", test_version2:"3.1.3"))
  {
    security_message(0);
    exit(0);
  }
}

# VMware Workstation
vmwtnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmwtnVer)
{
  if(version_in_range(version:vmwtnVer, test_version:"7.1.0", test_version2:"7.1.3")){
    security_message(0);
  }
}
