###############################################################################
# OpenVAS Vulnerability Test
# $Id: realty_web_base_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# Realty Web-Base Detection
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Realty Web-Base, a content management and customer communication
   suite is running at this host.";

if (description)
{
 script_id(100194);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Realty Web-Base Detection");

 script_summary("Checks for the presence of Realty Web-Base");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.realtywebware.com");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100194";
SCRIPT_DESC = "Realty Web-Base Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/cms",cgi_dirs());

foreach dir (dirs) {

    url = string(dir, "/admin/index.php"); 
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if( buf == NULL )continue; 
    
    if(egrep(pattern:"Realty Webware [0-9.]+", string: buf) &&
       egrep(pattern:"Set-Cookie: owner", string: buf) )
    {    

         if(strlen(dir)>0) {
            install=dir;
         } else {
            install=string("/");
         }

         vers = string("unknown");

	 version = eregmatch(pattern:"Realty Webware ([0-9.]+)", string:buf);

	 if(!isnull(version[1])) {
           vers = version[1];
	 }  

         tmp_version = string(vers," under ",install);
	 set_kb_item(name: string("www/", port, "/RealtyWebBase"), value: tmp_version);
   
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:realtywebware:realty_web-base:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

         info = string("\n\nRealty Web-Base Version '");
         info += string(vers);
         info += string("' was detected on the remote host in the following directory(s):\n\n");
         info += string(install, "\n"); 

         log_message(port:port,data:info);
         exit(0);
    }	 
}

exit(0);
