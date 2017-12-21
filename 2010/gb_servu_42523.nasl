###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_servu_42523.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# Serv-U Denial of Service and Security Bypass Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Serv-U is prone to denial-of-service and security-bypass
vulnerabilities.

Exploiting these issues can allow attackers to create directories
without having sufficient permissions, or crash the affected
application, resulting in denial-of-service conditions.

Versions prior to Serv-U 10.2.0.0 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100767");
 script_version("$Revision: 8187 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-08-31 14:30:50 +0200 (Tue, 31 Aug 2010)");
 script_bugtraq_id(42523);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Serv-U Denial of Service and Security Bypass Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42523");
 script_xref(name : "URL" , value : "http://www.serv-u.com/releasenotes/");
 script_xref(name : "URL" , value : "http://www.serv-u.com/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_rhinosoft_serv-u_detect.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

if(!version = get_kb_item(string("ftp/", port, "/Serv-U"))) {
 if(!version = get_kb_item(string("Serv-U/FTP/Ver"))) {
  exit(0);
 }  
}  

if(!isnull(version[1])) {
  vers = version[1];
}  

if(!isnull(vers)) {

    if(version_is_less(version:vers, test_version:"10.2") ) {
        security_message(port: port);
        exit(0);
    }
}

exit(0);

