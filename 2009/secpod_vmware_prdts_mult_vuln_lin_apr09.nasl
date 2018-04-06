###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_prdts_mult_vuln_lin_apr09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# VMware Products Multiple Vulnerabilities (Linux) Apr09
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker cause denial of service,
  local password information disclosure, arbitrary code execution, access to shared
  resources or heap overflow.
  Impact Level: System/Application";
tag_solution = "Upgrade your VMWares according to the below link.
  http://lists.vmware.com/pipermail/security-announce/2009/000054.html";

tag_summary = "The host is installed with VMWare products and are prone to
  Multiple Vulnerabilities.";

tag_affected = "VMware Workstation 6.5.1 and prior
  VMware Player 2.5.1 and prior
  VMware Server 2.0.1 and prior";
tag_insight = "For detailed information of the multiple vulnerabilities please refer to the
  links provided in references.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900703");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:48:30 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4916", "CVE-2008-3761", "CVE-2009-1146", "CVE-2009-1147",
                "CVE-2009-0909", "CVE-2009-0910", "CVE-2009-0177", "CVE-2009-1244");
  script_bugtraq_id(34373, 34471);
  script_name("VMware Products Multiple Vulnerabilities (Linux) Apr09");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0944");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2009-0005.html");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2009-0006.html");
  script_xref(name : "URL" , value : "http://lists.vmware.com/pipermail/security-announce/2009/000055.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_require_keys("VMware/Linux/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

# Check for VMware Player
vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer != NULL)
{
  if(version_is_less_equal(version:vmplayerVer, test_version:"2.5.1")){
    security_message(0);
  }
  exit(0);
}

# Check for VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer != NULL)
{
  if(version_is_less_equal(version:vmworkstnVer, test_version:"6.5.1")){
    security_message(0);
  }
  exit(0);
}

# Check for VMware Server
vmserverVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserverVer != NULL)
{
  if(version_in_range(version:vmserverVer, test_version:"1.0", test_version2:"1.0.8") ||
     version_in_range(version:vmserverVer, test_version:"2.0", test_version2:"2.0.0")){
    security_message(0);
  }
  exit(0);
}
