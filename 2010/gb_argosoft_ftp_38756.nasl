###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_argosoft_ftp_38756.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# ArGoSoft FTP Server .NET Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
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

tag_summary = "ArGoSoft FTP Server .NET is prone to a directory-traversal
vulnerability because it fails to sufficiently sanitize user-
supplied input.

Exploiting this issue can allow an attacker to upload and download
arbitrary files outside of the FTP server root directory. This could
help the attacker launch further attacks.

ArGoSoft FTP Server .NET 1.0.2.1 is vulnerable; other versions may
also be affected.";


if (description)
{
 script_id(100539);
 script_version("$Revision: 7573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-03-17 13:20:23 +0100 (Wed, 17 Mar 2010)");
 script_bugtraq_id(38756);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_name("ArGoSoft FTP Server .NET Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38756");
 script_xref(name : "URL" , value : "http://www.argosoft.com/rootpages/FtpServerNet/Default.aspx");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+ftpPort+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

banner = get_ftp_banner(port: ftpPort);  
if(!banner || "ArGoSoft" >!< banner)exit(0);     

version = eregmatch(pattern: "v.([0-9.]+)", string:banner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version: version[1], test_version: "1.0.2.1")) {
  security_message(port: ftpPort);
  exit(0);
}

exit(0);
