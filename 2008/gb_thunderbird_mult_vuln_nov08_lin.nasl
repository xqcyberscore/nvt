###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_mult_vuln_nov08_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities November-08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, spoofing attacks, sensitive information
  disclosure, and JavaScript code that can be executed with the privileges
  of the signed user.
  Impact Level: System";
tag_affected = "Thunderbird version prior to 2.0.0.18 on Linux.";
tag_solution = "Upgrade to Thunderbird version 2.0.0.18
  http://www.mozilla.com/en-US/thunderbird/all.html";
tag_summary = "The host is installed with Mozilla Thunderbird and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800060");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017",
                "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024",
                "CVE-2008-5052");
  script_bugtraq_id(32281);
  script_name("Mozilla Thunderbird Multiple Vulnerabilities November-08 (Linux)");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-48.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-50.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-52.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-55.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-56.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-58.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Thunderbird/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(!tbVer){
  exit(0);
}

# Grep for thunderbird version < 2.0.0.18
if(version_is_less(version:tbVer, test_version:"2.0.0.18")){
  security_message(0);
}
