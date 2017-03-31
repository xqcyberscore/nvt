###############################################################################
# OpenVAS Vulnerability Test
# $Id: TurnkeyForms_classifieds_authentication_bypass.nasl 5220 2017-02-07 11:42:33Z teissa $
#
# TurnkeyForms Local Classifieds 'Site_Admin/admin.php' Authentication
# Bypass Vulnerability
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

tag_summary = "TurnkeyForms Local Classifieds is prone to an authentication-bypass
  vulnerability.

  Attackers can exploit this issue to gain administrative access to
  the affected application.";


if (description)
{
 script_id(100032);
 script_version("$Revision: 5220 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-07 12:42:33 +0100 (Tue, 07 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(32282);
 script_cve_id("CVE-2008-6302");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("TurnkeyForms Local Classifieds 'Site_Admin/admin.php' Authentication Bypass Vulnerability");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/localclassifieds/", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/classifieds/Site_Admin/admin.php ");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if ( ereg(pattern: "^HTTP/1\.[01] +200", string: buf) &&
      egrep(pattern: '<title>Classifieds Administration</title>', string: buf)
    ) 
   {    
    security_message(port:port);
    exit(0);
   }
}

exit(0);
