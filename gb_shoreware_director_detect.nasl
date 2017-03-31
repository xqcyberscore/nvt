###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shoreware_director_detect.nasl 2834 2016-03-11 08:39:36Z benallard $
#
# ShoreTel ShoreWare Director Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103813";   

if (description)
{
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 2834 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 09:39:36 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2013-10-15 16:03:11 +0200 (Tue, 15 Oct 2013)");
 script_name("ShoreTel ShoreWare Director Detection");

   tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";


  script_tag(name : "summary" , value : tag_summary);

 script_summary("Checks for the presence of ShoreTel ShoreWare Director");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!port){
    port = 80;
}

if(!get_port_state(port)){
    exit(0);
}

dirs = make_list("/ShoreWareDirector/",cgi_dirs());

foreach dir (dirs) {

  url = dir + '/';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("ShoreWare Director Login</TITLE>" >< buf && "ShoreTel, Inc" >< buf && "password" >< buf) {

    vers = 'unknown';

    version = eregmatch(pattern:"ShoreTel ([^& ]+)&nbsp", string:buf);
    if(!isnull(version[1])) vers = version[1];

    _build = eregmatch(pattern:"Build ([^<]+)<", string:buf);
    if(!isnull(_build[1])) build = _build[1];

    set_kb_item(name:"ShoreWare_Director/installed", value:TRUE);
    set_kb_item(name: string("www/", port, "/ShoreWare_Director/version"), value: string(vers," under ",dir));
    set_kb_item(name: string("www/", port, "/ShoreWare_Director/build"), value: build);;

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:shoretel:shoreware_director:");
    if(isnull(cpe))
      cpe = 'cpe:/a:shoretel:shoreware_director';

    report_vers = vers; 
    if(build) report_vers += ', Build: ' + build;

    register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:port);
    log_message(data: build_detection_report(app:"ShoreWare_Director",version:report_vers,install:dir,cpe:cpe,concluded: version[0]),
                port);


  }  

} 

exit(0);
