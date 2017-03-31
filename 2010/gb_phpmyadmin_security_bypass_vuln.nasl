###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_security_bypass_vuln.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# phpMyAdmin 'phpinfo.php' Security bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the unauthenticated attackers to display
  information related to PHP.
  Impact Level: Application";
tag_affected = "phpMyAdmin version prior to 3.4.0-beta1.";
tag_insight = "The flaw is caused by missing authentication in the 'phpinfo.php' script
  when 'PMA_MINIMUM_COMMON' is defined. This can be exploited to gain knowledge
  of sensitive information by requesting the file directly.";
tag_solution = "Upgrade to phpMyAdmin version 3.4.0-beta1 or later
  http://www.phpmyadmin.net/home_page/downloads.php";
tag_summary = "The host is running phpMyAdmin and is prone to security bypass
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801494";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5373 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4481");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("phpMyAdmin 'phpinfo.php' Security bypass Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42485");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3238");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2010-10.php");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

## Get phpMyAdmin Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get phpMyAdmin path
if(dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the Attack Request
sndReq = http_get(item:string(dir, "/phpinfo.php"), port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Check the response
if(">Configuration<" >< rcvRes && ">PHP Core<" >< rcvRes &&
   ">Apache Environment<" >< rcvRes)
{
  security_message(port);
  exit(0);
}
