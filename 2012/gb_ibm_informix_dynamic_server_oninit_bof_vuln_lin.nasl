###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_informix_dynamic_server_oninit_bof_vuln_lin.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# IBM Informix Dynamic Server 'oninit.exe' Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.
  Impact Level: System/Application";
tag_affected = "IBM Informix Dynamic Server (IDS) 11.10 before 11.10.xC2W2 and 11.50 before 11.50.xC1";
tag_insight = "The flaw is due to a boundary error within the logging function in
  oninit.exe and can be exploited to cause a stack-based buffer overflow by
  sending a specially crafted request to TCP ports 9088 or 1526.";
tag_solution = "Upgrade to IBM Informix IDS version 11.50.xC1, 11.10.xC2W2 or later.
  For updates refer to http://www-01.ibm.com/software/data/informix/";
tag_summary = "This host is installed with IBM Informix Dynamic Server and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802291");
  script_version("$Revision: 8649 $");
  script_bugtraq_id(44192);
  script_cve_id("CVE-2010-4053");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-01-12 17:17:17 +0530 (Thu, 12 Jan 2012)");
  script_name("IBM Informix Dynamic Server 'oninit.exe' Buffer Overflow Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41913");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62619");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-216");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_informix_dynamic_server_detect_lin.nasl");
  script_require_keys("IBM/Informix/Dynamic/Server/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("IBM/Informix/Dynamic/Server/Lin/Ver");
if(version)
{
  ## Check for IBM Informix Dynamic Server (IDS) versions
  if(version_is_equal(version:version, test_version:"11.10") ||
     version_is_equal(version:version, test_version:"11.50")){
    security_message(0);
  }
}
