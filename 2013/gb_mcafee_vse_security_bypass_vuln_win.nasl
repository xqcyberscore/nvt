##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vse_security_bypass_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# McAfee VirusScan Enterprise Security Bypass Vulnerability (Windows)
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

tag_solution = "Apply patch from below link,
  http://go.microsoft.com/fwlink/?LinkId=194729

  *****
  NOTE: Ignore this warning, if above mentioned patch is applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code
  via malware that is correctly detected by this product.
  Impact Level: System/Application";

tag_affected = "McAfee VirusScan Enterprise versions 8.5i and 8.7i";
tag_insight = "Does not properly interact with the processing of hcp:// URLs by the
  Microsoft Help and Support Center.";
tag_summary = "This host is installed with McAfee VirusScan Enterprise and is
  prone to security bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803321");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2010-3496");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-04 10:50:36 +0530 (Mon, 04 Mar 2013)");
  script_name("McAfee VirusScan Enterprise Security Bypass Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2010-3496");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10012");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

## Variable Initialization
version = "";

## Get version from KB
version = get_kb_item("McAfee/VirusScan/Win/Ver");
if(version)
{
  ## Check for McAfee VirusScan Enterprise versions 8.5i or 8.7i
  if(version == "8.5i"|| version == "8.7i")
  {
    security_message(0);
    exit(0);
  }
}
