###############################################################################
# OpenVAS Vulnerability Test
# $Id: FtpXQ_36391.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# DataWizard FtpXQ Remote Denial of Service Vulnerability
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

tag_summary = "FtpXQ is prone to a remote denial-of-service vulnerability.

Remote attackers can cause the affected server to stop responding,
denying service to legitimate users.

FtpXQ 3.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100293");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_cve_id("CVE-2009-3545");
 script_bugtraq_id(36391);

 script_name("DataWizard FtpXQ Remote Denial of Service Vulnerability");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36391");
 script_xref(name : "URL" , value : "http://www.datawizard.net");
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

if(!banner = get_ftp_banner(port:port))exit(0);

if("FtpXQ" >!< banner)exit(0);

version = eregmatch(string: banner, pattern:"Version ([0-9.]+)");

if(!isnull(version[1])) {
 if(version_is_equal(version: version[1], test_version: "3.0")) {
  security_message(port:port);
 }
}   


exit(0); 

     
