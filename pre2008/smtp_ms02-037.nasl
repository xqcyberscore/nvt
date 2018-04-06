# OpenVAS Vulnerability Test
# $Id: smtp_ms02-037.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IMC SMTP EHLO Buffer Overrun
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
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

tag_summary = "A security vulnerability results
because of an unchecked buffer in the IMC code that
generates the response to the EHLO protocol command.
If the buffer were overrun with data it would result in
either the failure of the IMC or could allow the
attacker to run code in the security context of the IMC,
which runs as Exchange5.5 Service Account.

** OpenVAS only uses the banner header to determine
   if this vulnerability exists and does not check
   for or attempt an actual overflow.";

tag_solution = "see
http://www.microsoft.com/technet/security/bulletin/MS02-037.mspx";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11053");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5306);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-0698");
 name = "IMC SMTP EHLO Buffer Overrun";
 script_name(name);
 
		    
  summary = "Checks to see if remote IMC SMTP version is vulnerable to buffer overflow";
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
 
 family = "SMTP problems";
 script_family(family);
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_keys("SMTP/microsoft_esmtp_5");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
data = get_smtp_banner(port:port);
if(!data)exit(0);

if(!egrep(pattern:"^220.*Microsoft Exchange Internet.*", 
	 string:data))exit(0);

# needs to be 5.5.2656.59 or GREATER.
# this good:

#220 proliant.fdma.com ESMTP Server (Microsoft Exchange
#Internet Mail Service 5.5.2656.59) ready

#this old:

#220 proliant.fdma.com ESMTP Server (Microsoft Exchange
#Internet Mail Service 5.5.2653.13) ready

if(egrep(string:data, pattern:"Service.5\.[6-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.[3-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.2[7-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.26[6-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.265[6-9]"))
  exit(0);
security_message(port);

