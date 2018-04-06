###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_null_ptr_dos_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Firefox Browser designMode Null Pointer Dereference DoS Vulnerability - Linux
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful remote exploitation could result in denying the service.
  Impact Level: Application";
tag_affected = "Firefox version 3.x to 3.0.5 on Linux.";
tag_insight = "Null pointer dereferencing error occurs in the broswer which fails to validate
  the user input data when designMode module is enabled. These can be exploited
  via replaceChild or removeChild call, followed by a queryCommandValue,
  queryCommandState or queryCommandIndeterm call.";
tag_solution = "Upgerade to Firefox version 3.6.3 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800406");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0071");
  script_bugtraq_id(33154);
  script_name("Firefox Browser designMode Null Pointer Dereference DoS Vulnerability - Linux");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0220.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0223.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0224.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for firefox version 3.x to 3.0.5
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.5")){
  security_message(0);
}
