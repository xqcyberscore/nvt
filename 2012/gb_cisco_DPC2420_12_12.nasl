###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_DPC2420_12_12.nasl 3859 2016-08-19 09:18:21Z ckuerste $
#
# Cisco DPC2420 Cross Site Scripting / File Disclosure
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

tag_summary = "Cisco DPC2420 router is prone to a file disclosure and and to a XSS
vulnerability because it fails to sufficiently sanitize user
supplied data.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103620";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 3859 $");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_name("Cisco DPC2420 Cross Site Scripting / File Disclosure");

 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118711/Cisco-DPC2420-Cross-Site-Scripting-File-Disclosure.html");

 script_tag(name:"last_modification", value:"$Date: 2016-08-19 11:18:21 +0200 (Fri, 19 Aug 2016) $");
 script_tag(name:"creation_date", value:"2012-12-10 11:09:30 +0100 (Mon, 10 Dec 2012)");
 script_summary("Determine if it is possible to read the filename.gwc");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/webstar.html';

if(http_vuln_check(port:port, url:url,pattern:"<TITLE>Cisco Cable Modem")) {

  url = '/filename.gwc';

  if(http_vuln_check(port:port, url:url,pattern:"Model Number", extra_check:make_list("Serial Number","User Password"))) {
     
    security_message(port:port);
    exit(0);

  }  

}

exit(0);

