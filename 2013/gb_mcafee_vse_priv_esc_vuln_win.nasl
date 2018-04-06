##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vse_priv_esc_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# McAfee VirusScan Enterprise Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Successful exploitation will allow attackers to disable Anti-Virus, add
  unwanted exclusions or execute unspecified Metasploit Framework module.
  Impact Level: System/Application";

tag_affected = "McAfee VirusScan Enterprise versions prior to 8.8";
tag_insight = "Unspecified flaw allows attackers to escalate privileges.";
tag_solution = "Update to McAfee VirusScan Enterprise version 8.8 or later,
  http://www.mcafee.com/us/products/virusscan-enterprise.aspx";
tag_summary = "This host is installed with McAfee VirusScan Enterprise and is
  prone to privilege escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803320");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2010-5143");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-04 10:10:22 +0530 (Mon, 04 Mar 2013)");
  script_name("McAfee VirusScan Enterprise Privilege Escalation Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2010-5143");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10014");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
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

## Variable Initialization
version = "";

## Get version from KB
version = get_kb_item("McAfee/VirusScan/Win/Ver");
if(version)
{
  ## Check for McAfee VirusScan Enterprise versions prior to 8.8
  if(version_is_less(version:version, test_version:"8.8"))
  {
    security_message(0);
    exit(0);
  }
}
