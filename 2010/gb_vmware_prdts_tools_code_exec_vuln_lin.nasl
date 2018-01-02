###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_tools_code_exec_vuln_lin.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# VMware Products Tools Remote Code Execution Vulnerabilities (win)
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code.
  Impact Level: System/Application";
tag_solution = "For Upgrades refer the below link,
  http://www.vmware.com/security/advisories/VMSA-2010-0007.html";

tag_affected = "VMware Player 2.5.x before 2.5.4 build 246459,
  VMware Workstation 6.5.x before 6.5.4 build 246459";
tag_insight = "The flaw is due to error in 'tools' which does not properly access libraries.
  This allows attackers to execute arbitrary code by tricking a Windows guest
  OS user into clicking on a file that is stored on a network share.";
tag_summary = "The host is installed with VMWare products and are prone to
  remote code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801324");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1141", "CVE-2010-1142");
  script_bugtraq_id(39394, 39392);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("VMware Products Tools Remote Code Execution Vulnerabilies (win)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39198");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2010-0007.html");
  script_xref(name : "URL" , value : "http://lists.vmware.com/pipermail/security-announce/2010/000090.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_require_keys("VMware/Linux/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

# Check for VMware Player
vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.3"))
  {
    security_message(0);
    exit(0);
  }
}

#Check for VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.3"))
  {
    security_message(0);
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserVer)
{
  if(version_in_range(version:vmserVer, test_version:"2.0", test_version2:"2.0.1")){
    security_message(0);
  }
}

