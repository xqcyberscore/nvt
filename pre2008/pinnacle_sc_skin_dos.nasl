# OpenVAS Vulnerability Test
# $Id: pinnacle_sc_skin_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Pinnacle ShowCenter Skin DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host runs the Pinnacle ShowCenter web based interface.

The remote version of this software is vulnerable to a remote denial of 
service due to a lack of sanity checks on skin parameter.

With a specially crafted URL, an attacker can deny service of the ShowCenter 
web based interface.";

tag_solution = "Upgrade to the newest version of this software.";

# Ref: Marc Ruef <marc.ruef@computec.ch>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14824");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1699");
  script_bugtraq_id(11232);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Pinnacle ShowCenter Skin DoS");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8000);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if ( ! port ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=ATKopenvas", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  #try to detect errors
  if(egrep(pattern:"Fatal error.*loaduserprofile.*Failed opening required", string:r))
  {
    security_message(port);
  }
  http_close_socket(soc); 
 }
}
exit(0);
