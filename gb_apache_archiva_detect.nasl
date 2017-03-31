###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_archiva_detect.nasl 3803 2016-08-05 11:06:55Z antu123 $
#
# Apache Archiva Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100923"); 
 script_version("$Revision: 3803 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2016-08-05 13:06:55 +0200 (Fri, 05 Aug 2016) $");
 script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
 script_name("Apache Archiva Detection");
 
 script_tag(name : "summary" , value : "Detection of installed version of
 Apache Archiva.
 
 This script sends HTTP GET request and try to get the version from the
 response, and sets the result in KB.");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Set the version of Apache Archiva in KB");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
dir = "";
req = "";
buf = "";
arPort = 0;
version = 0;

##Get HTTP Port
if(!arPort = get_http_port(default:80)){
  exit(0);
}

dir = "/archiva";

## Send request and receive response
req = http_get(item:dir + "/index.action", port:arPort);
buf = http_send_recv(port:arPort, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 302 Found")
{
  req = http_get(item:dir + "/security/addadmin.action", port:arPort);
  buf = http_send_recv(port:arPort, data:req, bodyonly:FALSE);
}

if(buf == NULL) exit(0);

if("<title>Apache Archiva" >< buf && "The Apache Software Foundation" >< buf &&
   ("Artifact ID" >< buf || ">Login" >< buf))
{
  install = dir;

  vers = string("unknown");

  ## try to get version 
  version = eregmatch(string: buf, pattern: ">Apache Archiva( |&nbsp;-&nbsp;)([0-9.]+[^<]+)<",icase:TRUE);

  if(!isnull(version[2])){
    vers=chomp(version[2]);
  }

  set_kb_item(name: string("www/", arPort, "/apache_archiva"), value: string(vers," under Archiva"));
  set_kb_item(name:"apache_archiva/installed",value:TRUE);

  cpe = build_cpe(value:vers, exp:"^([0-9.A-Z-]+)", base:"cpe:/a:apache:archiva:");
  if(isnull(cpe))
    cpe = 'cpe:/a:apache:archiva';

  register_product(cpe:cpe, location:install, port:arPort);

  log_message(data: build_detection_report(app:"Apache Archiva",
                                           version:vers,
                                           install:install,
                                           cpe:cpe,
                                           concluded: version[0]),
                                           port:arPort);
}
exit(0);
