###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_slysoft_prdts_code_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# SlySoft Product(s) Code Execution Vulnerability
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

tag_impact = "Successful exploitation will let the attacker cause memory corruption and
  can allow remote code execution in the context of the affected system,
  which result in service crash.
  Impact Level: System/Application";
tag_affected = "SlySoft AnyDVD version prior to 6.5.2.6
  SlySoft CloneCD version 5.3.1.3 and prior
  SlySoft CloneDVD version 2.9.2.0 and prior
  SlySoft Virtual CloneDrive version 5.4.2.3 and prior";
tag_insight = "METHOD_NEITHER communication method for IOCTLs does not properly validate
  a buffer associated with the Irp object of user space data provided to
  the ElbyCDIO.sys kernel driver.";
tag_solution = "Upgrade to higher versions accordingly
  http://www.slysoft.com/en/download.html";
tag_summary = "This host is installed with SlySoft Product(s) and are prone
  to Code Execution Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800392");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-0824");
  script_bugtraq_id(34103);
  script_name("SlySoft Product(s) Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34269");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34289");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34287");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34288");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/501713/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_slysoft_prdts_detect.nasl");
  script_mandatory_keys("Slysoft/Products/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

# Grep the version for AnyDVD prior to 6.5.2.6
anydvdVer = get_kb_item("AnyDVD/Ver");
if(anydvdVer)
{
  if(version_is_less(version:anydvdVer, test_version:"6.5.2.6"))
  {
    security_message(0);
    exit(0);
  }
}

# Grep the version for CloneCD 5.3.1.3 and prior
clonecdVer = get_kb_item("CloneCD/Ver");
if(clonecdVer)
{
  if(version_is_less_equal(version:clonecdVer, test_version:"5.3.1.3"))
  {
    security_message(0);
    exit(0);
  }
}

# Grep the version for CloneDVD 2.9.2.0 and prior
clonedvdVer = get_kb_item("CloneDVD/Ver");
if(clonedvdVer)
{
  if(version_is_less_equal(version:clonedvdVer, test_version:"2.9.2.0"))
  {
    security_message(0);
    exit(0);
  }
}

# Grep the version for Virtual CloneDrive 5.4.2.3 and prior
vcdVer = get_kb_item("VirtualCloneDrive/Ver");
if(vcdVer)
{
  if(version_is_less_equal(version:vcdVer, test_version:"5.4.2.3")){
    security_message(0);
  }
}
