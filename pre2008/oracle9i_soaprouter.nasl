# OpenVAS Vulnerability Test
# $Id: oracle9i_soaprouter.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle 9iAS SOAP Default Configuration Vulnerability
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

tag_summary = "In a default installation of Oracle 9iAS v.1.0.2.2, it is possible to
deploy or undeploy SOAP services without the need of any kind of credentials.
This is due to SOAP being enabled by default after installation in order to 
provide a convenient way to use SOAP samples. However, this feature poses a 
threat to HTTP servers with public access since remote attackers can create
soap services and then invoke them remotely. Since SOAP services can
contain arbitrary Java code in Oracle 9iAS this means that an attacker
can execute arbitray code in the remote server.";

tag_solution = "Disable SOAP or the deploy/undeploy feature by editing
$ORACLE_HOME/Apache/Jserver/etc/jserv.conf and removing/commenting
the following four lines:
ApJServGroup group2 1 1 $ORACLE_HOME/Apache/Jserv/etc/jservSoap.properties
ApJServMount /soap/servlet ajpv12://localhost:8200/soap
ApJServMount /dms2 ajpv12://localhost:8200/soap
ApJServGroupMount /soap/servlet balance://group2/soap

Note that the port number might be different from  8200.
Also, you will need to change in the file 
$ORACLE_HOME/soap/werbapps/soap/WEB-INF/config/soapConfig.xml:
<osc:option name='autoDeploy' value='true' />
to
<osc:option name='autoDeploy' value='false' />



More information:
http://otn.oracle.com/deploy/security/pdf/ias_soap_alert.pdf
http://www.cert.org/advisories/CA-2002-08.html
http://www.kb.cert.org/vuls/id/476619

Also read:
Hackproofing Oracle Application Server from NGSSoftware:
available at http://www.nextgenss.com/papers/hpoas.pdf";


# References:
# http://otn.oracle.com/deploy/security/pdf/ias_soap_alert.pdf
#
# Also relevant:
# VU#476619
# CERT's CA-2002-08

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11227");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4289);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-1371");
 name = "Oracle 9iAS SOAP Default Configuration Vulnerability ";
 script_name(name);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
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

port = get_http_port(default:80);

# Make a request for /soap/servlet/soaprouter

 req = http_get(item:"/soap/servlet/soaprouter", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("SOAP Server" >< r)	
 	security_message(port);

 }
