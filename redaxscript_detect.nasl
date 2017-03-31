###############################################################################
# OpenVAS Vulnerability Test
# $Id: redaxscript_detect.nasl 2711 2016-02-23 10:16:13Z antu123 $
#
# Redaxscript Detection
#
# Authors:
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100121");
  script_version("$Revision: 2711 $");
  script_tag(name:"last_modification", value:"$Date: 2016-02-23 11:16:13 +0100 (Tue, 23 Feb 2016) $");
  script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Redaxscript Detection");

  script_summary("Checks for the presence of Redaxscript");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");

  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name : "URL" , value : "http://redaxscript.com/");

  script_tag(name : "summary", value : "This host is running Redaxscript a free, PHP and MySQL driven
Content Management System for small business and private websites.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/redaxscript", "/cms", "/php", cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:dir, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
  if(buf == NULL || buf !~ 'HTTP/1.. 200')
    continue;

  if ('"generator" content="Redaxscript' >< buf &&
      'Content could not be found.</p>' >!< buf)
  { 
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }  
    
    vers = string("unknown");

    ### try to get version 
    version = eregmatch(string: buf, pattern: '"generator" content="Redaxscript ([0-9.]+)"',icase:TRUE);
    
    if (!isnull(version[1])) {
       vers=chomp(version[1]);
    } 
    
    set_kb_item(name: string("www/", port, "/redaxscript"), value: vers);
    set_kb_item(name: "redaxscript/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base: "cpe:/a:redaxscript:redaxscript:");
    if (isnull(cpe))
      cpe = 'cpe:/a:redaxscript:redaxscript';  
       
    register_product(cpe:cpe, location:install, port:port);

    log_message(data:build_detection_report(app:"Redaxscript", version:vers,
                                            install:install, cpe:cpe,
                                            concluded:version[0]),
                                            port:port);      
  }
}

exit(0);
