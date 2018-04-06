# OpenVAS Vulnerability Test
# $Id: flash_ftp_server_directory_traversal.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Flash FTP Server Directory Traversal Vulnerability
#
# Authors:
# Noam Rathaus <noamr@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "Flash FTP Server easy-to-set-up FTP server for all Windows platforms.
Some bugs were found that will allow a malicious user to write and 
read anywhere on the disk.";

tag_solution = "Upgrade to the latest version of this software";

# Author: dr_insane
# Subject: Flash Ftp server 1.0 Directory traversal
# Date: January 1, 2004
# http://packetstormsecurity.nl/0401-exploits/Flash.txt
# http://www.secunia.co.uk/advisories/10522/

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11978");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1783");
 script_bugtraq_id(9350);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "Flash FTP Server Directory Traversal Vulnerability";
 
 script_name(name);
             

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");

 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
                  
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220 Flash FTP Server v(1\.|2\.[0-1]) ready", string:banner))security_message(port);

