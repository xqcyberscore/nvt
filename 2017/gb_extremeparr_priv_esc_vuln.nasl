###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_extremeparr_priv_esc_vuln.nasl 6900 2017-08-11 08:03:42Z cfischer $
#
# SUN Solaris Privilege Escalation Vulnerability (Extremeparr)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811259");
  script_version("$Revision: 6900 $");
  script_cve_id("CVE-2017-3622");
  script_bugtraq_id(97774);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-08-11 10:03:42 +0200 (Fri, 11 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-07-28 19:15:41 +0530 (Fri, 28 Jul 2017)");
  script_name("SUN Solaris Privilege Escalation Vulnerability (Extremeparr)");

  script_tag(name: "summary" , value:"This host is installed with Solaris
  and is prone to privilege escalation vulnerability.");

  script_tag(name: "vuldetect", value: "Get the installed version of
  Oracle Sun Solaris and check if the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to error in
  'Common Desktop Environment (CDE)' sub component of the application.");

  script_tag(name: "impact" , value: "Successful exploitation will allow local
  attackers to gain elevated privileges on the affected system.

  Impact Level: System");

  script_tag(name: "affected" , value: "Oracle Sun Solaris version 7, 8, 9 and
  10.
  Note: Oracle Sun Solaris version 7, 8, 9 are not supported anymore and will
  not be patched.");

  script_tag(name: "solution" , value: "Apply latest patch available for Oracle
  Sun Solaris version 10 or upgrade to Oracle Sun Solaris version 11. For details
  refer to,
  http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixSUNS");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixSUNS");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Solaris Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/solosversion");
  exit(0);
}

include("version_func.inc");


## Variable Initialization
version = "";

## Get Solaris Version
version = get_kb_item("ssh/login/solosversion");

##Solaris 10 is affected
if(version == "10")
{
  report = report_fixed_ver( installed_version:version, fixed_version:"Apply Patch or Upgrade to latest Release");
  security_message( data:report);
  exit(0);
}
exit(0);
