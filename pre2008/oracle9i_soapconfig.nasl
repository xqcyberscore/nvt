# OpenVAS Vulnerability Test
# $Id: oracle9i_soapconfig.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Oracle 9iAS SOAP configuration file retrieval
#
# Authors:
# Javier Fernandez-Sanguino <jfs@computer.org>
#
# Copyright:
# Copyright (C) 2003 Javier Fernandez-Sanguino
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

tag_summary = "In a default installation of Oracle 9iAS v.1.0.2.2.1, it is possible to
access some configuration files. These file includes detailed
information on how the product was installed in the server
including where the SOAP provider and service manager are located
as well as administrative URLs to access them. They might also
contain sensitive information (usernames and passwords for database
access).";

tag_solution = "Modify the file permissions so that the web server process
cannot retrieve it. Note however that if the XSQLServlet is present
it might bypass filesystem restrictions.


More information:
http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf
http://www.cert.org/advisories/CA-2002-08.html
http://www.kb.cert.org/vuls/id/476619

Also read:
Hackproofing Oracle Application Server from NGSSoftware:
available at http://www.nextgenss.com/papers/hpoas.pdf";


if(description)
{
 script_id(11224);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4290);
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-0568");
 name = "Oracle 9iAS SOAP configuration file retrieval";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2003 Javier Fernandez-Sanguino");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

# Make a request for the configuration file

# Note: this plugin can be expanded, I removed the call to 
# SQLConfig since it's already done directly in #10855
 config[0]="/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml";
# config[1]="/xsql/lib/XSQLConfig.xml"; # Already done by plugin #10855

 for(i = 0; config[i] ; i = i+1 ) {
     req = http_get(item:config[i], port:port);
     r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
     if(r == NULL) exit(0);
     if ( "SOAP configuration file" >< r )
	      security_message(port, data:string("The SOAP configuration file ",config[i]," can be accessed directly :\n" + r));
 } # of the for loop
