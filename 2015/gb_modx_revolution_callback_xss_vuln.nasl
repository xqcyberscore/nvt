###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_revolution_callback_xss_vuln.nasl 3497 2016-06-13 12:28:47Z benallard $
#
# MODX Revolution 'callback' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805235");
  script_version("$Revision: 3497 $");
  script_cve_id("CVE-2014-8992");
  script_bugtraq_id(71821);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 14:28:47 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-01-07 14:55:47 +0530 (Wed, 07 Jan 2015)");
  script_name("MODX Revolution 'callback' Parameter Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with MODX
  Revolution and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Check the md5sum of the affected
  .swf files");

  script_tag(name:"insight", value:"The error exists because the
  /manager/assets/fileapi/FileAPI.flash.image.swf script does not
  validate input to the 'callback' parameter before returning it to
  users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary HTML and script code in a
  users browser session in the context of an affected site.

  Impact Level: Application");

  script_tag(name:"affected", value:"MODX Revolution version 2.3.2-pl.");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "https://github.com/modxcms/revolution/issues/12161");
  script_summary("Check if MODX Revolution is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";
req = "";
res = "";
md5File = "";
resmd5 = "";


## Get http port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port state
if(!get_port_state(http_port)){
  exit(0);
}

#Check if host supports php
if(!can_host_php(port:http_port)){
  exit(0);
}

#iterate over possible paths
foreach dir (make_list_unique("/", "/modx", "/cms", cgi_dirs()))
{

  if( dir == "/" ) dir = "";

  ## Send and Receive the response
  req = http_get(item:string(dir, "/manager/index.php"), port:http_port);
  res = http_send_recv(port:http_port, data:req);

  ## confirm the application
  if(res && res =~ ">MODX CMF Manager Login<")
  {
    ## Construct the attack request
    url = dir + '/manager/assets/fileapi/FileAPI.flash.image.swf';

    ##MD5 Hash of .swf file
    md5File = 'ca807df6aa04b87a721239e38bf2e9e1';

    ## Send and Receive the response
    req = http_get(item:url, port:http_port);
    res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:TRUE);

    ##Calculate MD5 of response
    resmd5 = hexstr(MD5(res));

    #Check if md5 hashes match and Confirm exploit
    if(res && resmd5 == md5File)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
