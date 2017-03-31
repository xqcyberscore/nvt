###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mifi_2352.nasl 3100 2016-04-18 14:41:20Z benallard $
#
# Novatel Wireless MiFi 2352 Password Information Disclosure Vulnerability
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

tag_summary = "MiFi 2352 is prone to an information-disclosure vulnerability that may
expose sensitive information.

Successful exploits will allow authenticated attackers to obtain
passwords, which may aid in further attacks.

MiFi 2352 access point firmware 11.47.17 is vulnerable; other versions
may also be affected.";


if (description)
{
 script_id(103115);
 script_version("$Revision: 3100 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:41:20 +0200 (Mon, 18 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-03-10 13:28:46 +0100 (Thu, 10 Mar 2011)");
 script_bugtraq_id(37962);
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");
 script_name("Novatel Wireless MiFi 2352 Password Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/37962");
 script_xref(name : "URL" , value : "http://www.novatelwireless.com/");
 script_xref(name : "URL" , value : "http://www.securitybydefault.com/2010/01/vulnerabilidad-en-modemrouter-3g.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if MiFi 2352 is prone to an information-disclosure vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/config.xml.sav"); 

  if(http_vuln_check(port:port, url:url,pattern:"</WiFi>",extra_check: make_list("<ssid>","<Secure>","<keyindex>"))) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
