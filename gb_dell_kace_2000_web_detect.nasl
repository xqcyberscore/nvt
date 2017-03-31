###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_2000_web_detect.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Dell KACE K2000 Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "The web interface for the  Dell KACE K2000 is running at this Host.";

if (description)
{
 
 script_id(103317);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2011-11-11 10:17:05 +0100 (Fri, 11 Nov 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Dell KACE K2000 Detection");
 
 script_summary("Checks for the presence of Dell KACE K2000");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("X-KACE-Version/banner");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.kace.com/products/systems-deployment-appliance");
 exit(0);
}

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103317";
SCRIPT_DESC = "Dell KACE K2000 Detection";

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);


 if(egrep(pattern: "X-KACE-Version:", string: banner, icase: TRUE))
 {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: banner, pattern: "X-KACE-Version: ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/dell_kace_version"), value: string(vers));

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/h:dell:kace_k2000_systems_deployment_appliance:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("Dell KACE K2000 Version '");
    info += string(vers);
    info += string("' was detected on the remote host.\n\n");

       if(report_verbosity > 0) {
         log_message(port:port,data:info);
       }
       exit(0);

 }

exit(0);

