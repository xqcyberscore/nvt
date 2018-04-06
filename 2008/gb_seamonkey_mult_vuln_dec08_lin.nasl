###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_mult_vuln_dec08_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Mozilla Seamonkey Multiple Vulnerabilities December-08 (Linux)
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

tag_summary = "The host is installed with Mozilla Seamonkey and is prone
  to multiple vulnerabilities.

  Vulnerability:
  Refer to the reference links for more information on the vulnerabilities.";

tag_impact = "Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, sensitive information disclosure, cross
  site scripting attacks and execute JavaScript code with chrome privileges.
  Impact Level: System";
tag_affected = "Seamonkey version prior to 1.1.14 on Linux.";
tag_solution = "Upgrade to Seamonkey version 1.1.14 or later
  http://www.seamonkey-project.org/releases/";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800093");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503",
                "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510",
                "CVE-2008-5511", "CVE-2008-5512");
  script_bugtraq_id(32882);
  script_name("Mozilla Seamonkey Multiple Vulnerabilities December-08 (Linux)");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-60.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-61.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-64.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-65.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-66.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-67.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-68.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Seamonkey/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(!smVer){
  exit(0);
}

# Seamonkey version < 1.1.14
if(version_is_less(version:smVer, test_version:"1.1.14")){
  security_message(0);
}
