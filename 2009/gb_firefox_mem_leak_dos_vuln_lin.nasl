###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mem_leak_dos_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Firefox Browser Libxul Memory Leak Remote DoS Vulnerability - Linux
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

tag_impact = "Successful exploitation could result in denying the service.
  Impact Level: Application";
tag_affected = "Firefox version 3.0.2 to 3.0.5 on Linux.";
tag_insight = "The Browser fails to validate the user input data in Libxul, which leads
  to memory consumption or crash.";
tag_solution = "Upgrade to Firefox version 3.6.3 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800402");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5822");
  script_name("Firefox Browser Libxul Memory Leak Remote DoS Vulnerability - Linux");
  script_xref(name : "URL" , value : "http://liudieyu0.blog124.fc2.com/blog-entry-6.html");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0812-exploits/mzff_libxul_ml.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
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

# Grep for firefox version 3.0.2 to 3.0.5
if(version_in_range(version:ffVer, test_version:"3.0.2",
                                  test_version2:"3.0.5")){
  security_message(0);
}
