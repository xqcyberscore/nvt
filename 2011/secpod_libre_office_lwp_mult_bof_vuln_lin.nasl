###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_libre_office_lwp_mult_bof_vuln_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# LibreOffice LWP File Processing Multiple Buffer Overflow Vulnerabilities (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: System/Application.";
tag_affected = "LibreOffice version prior to 3.3.3";

tag_insight = "The flaws are due to errors in the import filter when processing Lotus
  Word Pro (LWP) files and can be exploited to cause a stack-based buffer
  overflow via a specially crafted file.";
tag_solution = "Upgrade to LibreOffice version 3.3.3 or 3.4.0 or later.
  For updates refer to http://www.libreoffice.org/download/";
tag_summary = "This host is installed with LibreOffice and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902700");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-2685");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("LibreOffice LWP File Processing Multiple Buffer Overflow Vulnerabilities (Linux)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_require_keys("LibreOffice/Linux/Ver");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44996/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/953183");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
officeVer = get_kb_item("LibreOffice/Linux/Ver");
if(!officeVer){
  exit(0);
}

## Check for LibreOffice version less than 3.3.3 => 3.3.301
if(version_is_less(version:officeVer, test_version:"3.3.301")){
  security_message(0);
}
