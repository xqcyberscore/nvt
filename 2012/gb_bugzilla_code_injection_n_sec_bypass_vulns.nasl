###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_code_injection_n_sec_bypass_vulns.nasl 8200 2017-12-20 13:48:45Z cfischer $
#
# Bugzilla LDAP Code Injection And Security Bypass Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information and bypass security restriction on the affected site.
  Impact Level: Application";
tag_affected = "Bugzilla 2.x and 3.x to 3.6.11, 3.7.x and 4.0.x to 4.0.7, 4.1.x and
  4.2.x to 4.2.2, and 4.3.x to 4.3.2";
tag_insight = "The flaws are due to
  - When the user logs in using LDAP, the username is not escaped when building
    the uid=$username filter which is used to query the LDAP directory. This
    could potentially lead to LDAP injection.
  - Extensions are not protected against directory browsing and users can access
    the source code of the templates which may contain sensitive data.";
tag_solution = "Upgrade to Bugzilla version 4.0.8, 4.2.3, 4.3.3 or higher
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "The host is running Bugzilla and is prone to code injection
  and security bypass vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.892672";
CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8200 $");
  script_cve_id("CVE-2012-4747, CVE-2012-3981");
  script_bugtraq_id(55349);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:48:45 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-09-11 11:13:14 +0530 (Tue, 11 Sep 2012)");
  script_name("Bugzilla LDAP Code Injection And Security Bypass Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.6.10/");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=785470");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=785511");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=785522");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_require_keys("bugzilla/installed");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variables Initialization
dir  = "";
disc  = "/extensions/create.pl";
bugPort = 0;

## Get HTTP Port
if(!bugPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port state
if(!get_port_state(bugPort)){
  exit(0);
}

## Get Bugzilla Installed Location
if(!dir = get_dir_from_kb(port:bugPort, app:"bugzilla")){
  exit(0);
}

## Confirm the Attack by opening the create.pl file under /extensions
if(http_vuln_check(port:bugPort, url:dir + disc, check_header: TRUE,
   pattern:"^\#!\/usr\/bin\/perl -w", extra_check:["^use Bugzilla\;$",
   "my \$base_dir = bz_locations\(\)->\{'extensionsdir'\}\;"]))
{
  security_message(bugPort);
  exit(0);
}
