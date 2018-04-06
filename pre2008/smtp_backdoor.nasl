# OpenVAS Vulnerability Test
# $Id: smtp_backdoor.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: SMTP server on a strange port
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

tag_summary = "This SMTP server is running on a non standard port. 
This might be a backdoor set up by crackers to send spam
or even control your machine.";

tag_solution = "Check and clean your configuration";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18391");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 name = "SMTP server on a strange port";
 script_name(name);
 

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Malware");

 script_dependencies("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

port = get_kb_item("Services/smtp");
if (port && port != 25 && port != 465 && port != 587) security_message(port);
