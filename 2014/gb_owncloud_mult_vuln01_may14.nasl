###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_vuln01_may14.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# ownCloud Multiple Vulnerabilities - 01 May14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:owncloud:owncloud";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804288";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7000 $");
  script_cve_id("CVE-2013-2041", "CVE-2013-2086", "CVE-2013-2044", "CVE-2013-2047",
                "CVE-2013-2048", "CVE-2013-2085", "CVE-2013-2089");
  script_bugtraq_id(59951, 66540, 59962, 66542, 59975, 59949, 59968);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-05-06 19:11:33 +0530 (Tue, 06 May 2014)");
  script_name("ownCloud Multiple Vulnerabilities - 01 May14");

  tag_summary =
"This host is installed with ownCloud and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- Insufficient validation of user-supplied input passed via 'tag' GET parameter
to templates/js_tpl.php script, the 'dir' GET parameter to
apps/files/ajax/newfile.php script, the 'redirect_url' parameter to the
index.php script.
- An error in configuration loader which includes private data such as CSRF
tokens in a JavaScript file.
- An error in the index.php script due to the autocomplete setting being
enabled for the 'password' parameter.
- An insufficient permission check for sensitive transactions.
- Insufficient sanitization of user-supplied input via the 'dir' GET parameter
to apps/files_trashbin/index.php script.
- Insufficient verification of user-supplied files for uploading.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary PHP
code, gain access to arbitrary local files, execute API commands as
administrator, conduct cross-site request forgery attacks, gain access to a
user's account or password, redirect users to arbitrary web sites and conduct
phishing attacks, obtain sensitive information and execute arbitrary
script code in a user's browser within the trust relationship between their
browser and the server.

Impact Level: System/Application";

  tag_affected =
"ownCloud Server 5.0.x before version 5.0.6";

  tag_solution =
"Upgrade to ownCloud version 5.0.6 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-026");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-020");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-025");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-023");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-022");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-027");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-021");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ownPort = "";
ownVer = "";

## get the port
if(!ownPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get version
if(!ownVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ownPort)){
  exit(0);
}

## Grep for vulnerable version
if(version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.6"))
{
  security_message(port:ownPort);
  exit(0);
}
