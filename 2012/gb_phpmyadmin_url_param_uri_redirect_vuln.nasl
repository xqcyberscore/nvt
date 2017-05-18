###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_url_param_uri_redirect_vuln.nasl 6022 2017-04-25 12:51:04Z teissa $
#
# phpMyAdmin 'url' Parameter URI Redirection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to redirect users to
  arbitrary web sites and conduct phishing attacks.
  Impact Level: Application";
tag_affected = "phpMyAdmin version 3.4.0";
tag_insight = "The flaw is due to an improper validation of user-supplied input to
  the 'url' parameter in url.php, which allows attackers to redirect a user to
  an arbitrary website.";
tag_solution = "Upgrade to phpMyAdmin version 3.4.1 or later.
  For updates refer to http://www.phpmyadmin.net/home_page/downloads.php";
tag_summary = "This host is running phpMyAdmin and is prone to URI redirection
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802607";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6022 $");
  script_bugtraq_id(47943);
  script_cve_id("CVE-2011-1941");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Tue, 25 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-02-09 17:17:17 +0530 (Thu, 09 Feb 2012)");
  script_name("phpMyAdmin 'url' Parameter URI Redirection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44641");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/47943");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67569");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2011-4.php");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpMyAdmin/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
req = "";
res = "";
port = 0;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Get phpMyAdmin Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct attack request
url = string("http://", get_host_name(), dir, "/ChangeLog");
req = http_get(item: string(dir, "/url.php?url=", url), port: port);
if(!isnull(req))
{
  pattern = string("Location: ", url);

  ## Send attack request and receive the response
  res = http_send_recv(port:port, data:req);
  if(!isnull(res))
  {
    ## Confirm Vulnerability
    if(res =~ "HTTP/1.. 302" && pattern >< res){
      security_message(port);
    }
  }
}
