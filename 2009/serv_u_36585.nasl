###############################################################################
# OpenVAS Vulnerability Test
# $Id: serv_u_36585.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Serv-U 'SITE SET TRANSFERPROGRESS ON' Command Remote Denial of Service Vulnerability
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

tag_summary = "Serv-U is prone to a remote denial-of-service vulnerability.

Successfully exploiting this issue will allow attackers to deny
service to legitimate users.

Serv-U 7.0.0.1 through 8.2.0.3 are vulnerable; other versions may also
be affected.";

tag_solution = "The vendor has released an update. Please see the references
for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100338");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-11-04 20:13:20 +0100 (Wed, 04 Nov 2009)");
 script_bugtraq_id(36585);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Serv-U 'SITE SET TRANSFERPROGRESS ON' Command Remote Denial of Service Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_rhinosoft_serv-u_detect.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36585");
 script_xref(name : "URL" , value : "http://www.serv-u.com/");
 script_xref(name : "URL" , value : "http://www.serv-u.com/releasenotes/");
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

    if( version_in_range(version:vers, test_version:"7.0.0.1", test_version2:"8.2.0.3") ) {
        security_message(port: port);
        exit(0);
    }
}

exit(0);

