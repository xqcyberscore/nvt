# OpenVAS Vulnerability Test
# $Id: wu_ftpd_rnfr_file_overwrite.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: wu-ftpd rnfr file overwrite
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote Wu-FTPd server seems to be vulnerable to a remote flaw.

This version contains a flaw that may allow a malicious user to overwrite 
arbitrary files.  The issue is triggered when an attacker sends a specially 
formatted rnfr command.  This flaw will allow a remote attacker to overwrite
any file on the system.

*** OpenVAS solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.";

tag_solution = "Upgrade to Wu-FTPd 2.4.2 or newer";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14302");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-1999-0081");
 script_xref(name:"OSVDB", value:"8717");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 name = "wu-ftpd rnfr file overwrite";
 script_name(name);
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		  
 script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl", "secpod_ftp_anonymous.nasl");
 script_require_keys("ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.([0-3]\.|4\.[01])).*", string:banner))
	security_message(port);

