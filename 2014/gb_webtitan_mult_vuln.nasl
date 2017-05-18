###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webtitan_mult_vuln.nasl 5816 2017-03-31 10:16:41Z cfi $
#
# WebTitan Multiple Security Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804469");
  script_version("$Revision: 5816 $");
  script_cve_id("CVE-2014-4306", "CVE-2014-4307");
  script_bugtraq_id(67921);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 12:16:41 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2014-06-23 18:10:58 +0530 (Mon, 23 Jun 2014)");
  script_name("WebTitan Multiple Security Vulnerabilities");

  tag_summary = "This host is running WebTitan and is prone to multiple vulnerabilities.";

  tag_vuldetect = "Send a crafted default credential via HTTP GET request and check whether it
is able to get information or not.";

  tag_insight = "- The categories-x.php script not properly sanitizing user-supplied input to
   the 'sortkey' GET parameter.
 - Input passed via the 'fname' and 'logfile' parameters is not properly
   sanitized upon submission to logs-x.php.
 - Input passed via the 'ldapserver' parameter is not properly sanitized
   upon submission to the users-x.php script.
 - Input passed via the 'ntpserversList' POST parameter is not properly
   sanitized upon submission to the time-x.php script.
 - Input passed via the 'reportid' parameter is not properly sanitized upon
   submission to the schedulereports-x.php script.
 - Input passed via the 'delegated_admin' POST parameter is not properly
   sanitized upon submission to the reporting-x.php script.
 - The autoconf-x.php, contentfiltering-x.php, license-x.php, msgs.php, and
   reports-drill.php scripts not requiring authentication.";

  tag_impact = "Successful exploitation will allow remote attackers to trivially gain privileged
access to the device, execute arbitrary commands and gain access to arbitrary
files.

Impact Level: System/Application";

  tag_affected = "WebTitan version 4.01 (Build 68)";

  tag_solution = "Upgrade to WebTitan version 4.04 or later,
For updates refer to http://www.webtitan.com ";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/33699");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Jun/35");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2014/06/sec-consult-sa-20140606-0-multiple.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
webReq = "";
webRes = "";
kPort = 0;

kPort = get_http_port(default:80);
if(!can_host_php(port:kPort)){
  exit(0);
}

webRes = http_get_cache(item:"/login.php",  port:kPort);

##Confirm Application
if(">WebTitan<" >< webRes && "Copperfasten Technologies" >< webRes)
{
  url = '/categories-x.php?getcategories&sortkey=name)%20limit%205;--';

  ## Check the response to confirm vulnerability
  if(http_vuln_check(port:kPort, url:url, check_header:TRUE,
     pattern: "records.:.*categoryid.:.*:.SYSTEM",
     extra_check:"totalRecords"))
  {
    security_message(kPort);
    exit(0);
  }
}
