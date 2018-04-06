##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_address_book_mult_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# PHP Address Book Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.

Impact Level: Application";

tag_affected = "PHP Address Book 7.0 and prior";

tag_insight = "Multiple flaws are caused by improper validation of user supplied
input by the 'preferences.php', 'group.php', 'index.php' and 'translate.php'
scripts, which allows attackers to execute arbitrary HTML and script code in a
user's browser session in the context of an affected site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running PHP Address Book and is prone to multiple
cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902838");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(53598);
  script_cve_id("CVE-2012-2903");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-24 15:15:15 +0530 (Thu, 24 May 2012)");
  script_name("PHP Address Book Multiple Cross Site Scripting Vulnerabilities");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_address_book_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("PHP-Address-Book/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49212");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75703");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18899");
  script_xref(name : "URL" , value : "http://sourceforge.net/tracker/?func=detail&aid=3527242&group_id=157964&atid=805929");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get PHP Address Book Location
if(!dir = get_dir_from_kb(port:port, app:"PHP-Address-Book")){
  exit(0);
}

## Construct attack request
url = dir + '/index.php?group="<script>alert(document.cookie)</script>';

## Try XSS and check the response to confirm vulnerability
if(http_vuln_check( port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document.cookie\)</script>",
                    extra_check: 'content=\"PHP-Addressbook')) {
  security_message(port);
}
