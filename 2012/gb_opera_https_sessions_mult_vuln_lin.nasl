###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_https_sessions_mult_vuln_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Opera 'HTTPS-Session' Multiple Vulnerabilities (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to overwrite or
delete arbitrary cookies via a Set-Cookie header in an HTTP response, which
results into cross site scripting, cross site request forgery and denial of
service attacks.

Impact Level: Application";

tag_affected = "Opera version 11.50 and prior on Linux";

tag_insight = "Multiple flaws are due to not properly restricting modifications
to cookies established in HTTPS sessions.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Opera and is prone to multiple
vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802737");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2008-7297");
  script_bugtraq_id(49134);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-09 16:56:54 +0530 (Mon, 09 Apr 2012)");
  script_name("Opera 'HTTPS-Session' Multiple Vulnerabilities (Linux)");
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2008/11/cookie-forcing.html");
  script_xref(name : "URL" , value : "http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("version_func.inc");

## Variable Initialization
operaVer = "";

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version < 11.50
if(version_is_less_equal(version:operaVer, test_version:"11.50")){
  security_message(0);
}
