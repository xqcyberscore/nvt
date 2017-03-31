###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_maian_gallery_multiple_vuln.nasl 3549 2016-06-17 12:10:37Z antu123 $
#
# Maian Gallery Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805648");
  script_version("$Revision: 3549 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-17 14:10:37 +0200 (Fri, 17 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-06-09 15:25:55 +0530 (Tue, 09 Jun 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Maian Gallery Multiple Vulnerabilities");

  script_tag(name: "summary" , value:"The host is installed with Maian Gallery
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name: "insight" , value:"Multiple flaws exist as
  - Input passed to the 'index.php' script is not properly sanitised before being
    returned to the user.
  - Input passed to the 'cryptographp.php' script is not properly sanitised
    before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to  execute arbitrary script code in a user's browser within the
  trust relationship between their browser and the server and maliciously
  control the way a web application functions.

  Impact Level: Application");

  script_tag(name:"affected", value:"Maian Gallery version 2.0");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/132154");

  script_summary("Check if Maian Galleryn is prone to SQL");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

##
### Code Starts Here
##

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
mgPort = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
mgPort = get_http_port(default:80);
if(!mgPort){
 mgPort = 80;
}

## Check the port status
if(!get_port_state(mgPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:mgPort)){
  exit(0);
}

# Iterate over possible paths
# Application is not that much important so
# detect NVT is not created.
foreach dir (make_list_unique("/", "/gallery", "/maian_gallery", cgi_dirs()))
{

  if( dir == "/" ) dir = "";

  ##Send Request and Receive Response
  sndReq = http_get(item:string(dir,"/index.php"), port:mgPort);
  rcvRes = http_keepalive_send_recv(port:mgPort, data:sndReq);

  #Confirm application
  if("Maian Gallery" >< rcvRes)
  {
    ##Construct Attack URL
    url = dir + "/index.php?cmd=search&keywords=1&search_type=";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:mgPort, url:url, check_header:FALSE,
                       pattern:"You have an error in your SQL syntax"))
    {
      security_message(port:mgPort);
      exit(0);
    }
  }
}

exit(99);
