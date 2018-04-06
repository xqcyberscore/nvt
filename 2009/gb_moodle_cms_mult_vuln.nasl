###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_cms_mult_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Moodle CMS Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow remote attackers to cause Cross Site
  Scripting attacks, can gain sensitive information about the user or the
  remote host or can delete unauthorised posts through injecting malicious
  web scripts.

  Impact level: System/Application";

tag_affected = "Moodle version from 1.6 prior to 1.6.9,
  Moodle version from 1.7 prior to 1.7.7,
  Moodle version from 1.8 prior to 1.8.8 and 
  Moodle version from 1.9 prior to 1.9.4 on all platforms.";
tag_insight = "Multiple flaws are due to
  - Vulnerability in post.php for IMG tag which allows unauthorised access
    to user's posts.
  - XSS Vulnerability in course/lib.php which allows injection of arbitrary
    web scripts or malicious HTML codes while displaying the log report in
    browser due to lack of sanitization.
  - Unspecified vulnerability in the Calendar export feature which causes
    conducting brute force attacks.
  - XSS Vulnerability in blocks/html/block_html.php which allows injection
    of arbitracy scripts of malformed HTML codes injection.";
tag_solution = "Upgrade to latest version 1.6.9, 1.7.7, 1.8.8 and 1.9.4
  http://moodle.org/downloads";
tag_summary = "This host is running Moodle CMS and is prone to Multiple
  Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800240");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-0499", "CVE-2009-0500", "CVE-2009-0501", "CVE-2009-0502");
  script_bugtraq_id(33617, 33615, 33612, 32402);
  script_name("Moodle CMS Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://moodle.org/security");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/02/04/1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Moodle/Version");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

moodlePort = get_http_port(default:80);
if(!moodlePort){
  exit(0);
}

if(!get_kb_item(string("www/", moodlePort, "/moodle")))exit(0);

moodleVer = get_kb_item("Moodle/Version");
if(!moodleVer){
  exit(0);
}

# Grep for Moodle CMS Version
if(version_in_range(version:moodleVer, test_version:"1.6", test_version2:"1.6.8") ||
   version_in_range(version:moodleVer, test_version:"1.7", test_version2:"1.7.6") ||
   version_in_range(version:moodleVer, test_version:"1.8", test_version2:"1.8.7") ||
   version_in_range(version:moodleVer, test_version:"1.9", test_version2:"1.9.3")){
  security_message(moodlePort);
}
